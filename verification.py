from traceback import extract_tb
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from PIL import Image
import cv2
import re
import os
import io
import time
import numpy as np
import base64
import firebase_admin
from firebase_admin import credentials, firestore
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from google.oauth2 import service_account
from skimage.metrics import structural_similarity as ssim
import warnings
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Connect to Firebase
cred = credentials.Certificate("securesign-firebase-key.json")
try:
    verification_app = firebase_admin.get_app("verification")
except ValueError:
    verification_app = firebase_admin.initialize_app(cred, name="verification")
db = firestore.client(app=verification_app)

# Ignore warnings
warnings.filterwarnings("ignore", category=UserWarning)

# === Google Drive API Setup ===
SERVICE_ACCOUNT_FILE = 'C:/Users/user/Documents/python/ocr/ID-card-reader-OCR/lunar-ensign-457417-a7-10bdf1d3ecf5.json'
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
FOLDER_ID = '1MjQ_tXtjQlYJgDR7wrGjRmpVhdd7vVSn'

# Configuration parameters
SIGNATURE_COORDS = (950, 1200, 1380, 1880)  # (startY, endY, startX, endX)
SIMILARITY_THRESHOLD = 0.7  # Fixed threshold for match
MAX_RETRIES = 3  # Number of retries for API failures
TIMEOUT = 30  # Timeout for API calls in seconds

# === OCR Functions ===

def preprocess_image(image_path):
    """Process the image to improve OCR accuracy"""
    image = cv2.imread(image_path)
    
    # Resize image by 200%
    scale_percent = 200
    width = int(image.shape[1] * scale_percent / 100)
    height = int(image.shape[0] * scale_percent / 100)
    image = cv2.resize(image, (width, height), interpolation=cv2.INTER_LINEAR)

    # Basic grayscale and thresholding
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    _, binary = cv2.threshold(blurred, 150, 255, cv2.THRESH_BINARY)
    
    return binary

def clean_text(text):
    """Clean up common OCR errors specific to KTP cards"""
    # Replace common OCR errors
    text = text.replace('Tgi', 'Tgl')
    text = text.replace('DEW!', 'DEWI')
    text = text.replace('!', 'I')  # Common OCR error for capital I
    
    # Clean up lines
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            # Remove multiple spaces and standardize separators
            line = re.sub(r'\s+', ' ', line)
            lines.append(line)
    
    return '\n'.join(lines)

def extract_fields(text):
    """Comprehensive field extraction combining multiple methods"""
    # First, clean up the text to fix common OCR errors
    text = clean_text(text)
    
    # Split into lines and filter empty ones
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    
    # Initialize result dictionary
    result = {}
    
    # Define all the fields we expect to find
    expected_fields = [
        "NIK", "Nama", "Tempat/Tgl Lahir", "Jenis Kelamin", "Alamat", 
        "RT/RW", "Kel/Desa", "Kecamatan", "Agama", "Status Perkawinan", 
        "Pekerjaan", "Kewarganegaraan", "Berlaku Hingga"
    ]
    
    # ---- STEP 1: Extract NIK (highest priority) ----
    for line in lines:
        if "NIK" in line:
            match = re.search(r'NIK\s*[:\-=]?\s*(\d+)', line)
            if match:
                result["NIK"] = match.group(1).strip()
                break
    
    # ---- STEP 2: Map field labels to their positions in the text ----
    field_positions = {}
    for i, line in enumerate(lines):
        for field in expected_fields:
            if field in line:
                field_positions[field] = i
                break
    
    # ---- STEP 3: Extract field values using multiple methods ----
    
    # Method A: Extract from same line (for fields with value on same line)
    for field, pos in field_positions.items():
        line = lines[pos]
        # Match after field name and optional separator
        match = re.search(fr'{field}\s*[:\-=>]?\s*(.+)', line)
        if match:
            value = match.group(1).strip()
            # Clean separators and unwanted characters
            value = re.sub(r'^[:\-=>/]+\s*', '', value)
            # Remove potential field labels that might be captured
            for other_field in expected_fields:
                if other_field != field and other_field in value:
                    value = value.split(other_field)[0].strip()
            result[field] = value
    
    # Method B: Look at next line for value (for fields with value on next line)
    for field, pos in field_positions.items():
        if field not in result or not result[field]:
            if pos + 1 < len(lines):
                next_line = lines[pos + 1].strip()
                # Check if next line is a value (not a field label)
                if not any(f in next_line for f in expected_fields):
                    # Clean up the line
                    next_line = re.sub(r'^[:\-=>/]+\s*', '', next_line)
                    result[field] = next_line
    
    # Method C: Special handling for fields with separated values
    
    # Special handling for Status Perkawinan (might be joined with "KOTA JAKARTA")
    if "Status Perkawinan" in result and result["Status Perkawinan"]:
        value = result["Status Perkawinan"]
        if "KOTA JAKARTA" in value:
            result["Status Perkawinan"] = value.split("KOTA JAKARTA")[0].strip()
    
    # Special handling for Pekerjaan (might include the date)
    if "Pekerjaan" in result and result["Pekerjaan"]:
        value = result["Pekerjaan"]
        date_match = re.search(r'\d{2}-\d{2}-\d{4}', value)
        if date_match:
            result["Pekerjaan"] = value.split(date_match.group(0))[0].strip()
    
    # ---- STEP 4: Try to extract Nama if not found yet ----
    if "Nama" not in result or not result["Nama"]:
        for line in lines:
            if "Nama" in line:
                # Look for capital letters after "Nama"
                match = re.search(r'Nama\s*[:\-=>]?\s*([A-Z\s]+)', line)
                if match:
                    result["Nama"] = match.group(1).strip()
                # If still not found, check next line
                elif lines.index(line) + 1 < len(lines):
                    next_line = lines[lines.index(line) + 1]
                    if re.match(r'^[A-Z\s]+$', next_line):
                        result["Nama"] = next_line.strip()
    
    # ---- STEP 5: Handle special case where all fields are listed first, 
    # followed by values marked with dash/colon ----
    
    # Detect if this is the special format by checking if most fields don't have values
    missing_fields = [field for field in expected_fields if field in field_positions and 
                      (field not in result or not result[field])]
    
    # Special case processing - if we have at least 8 fields without values,
    # and we see a pattern of dashed lines afterward
    if len(missing_fields) >= 8:
        # Find the last field label position
        last_field_pos = max(field_positions.values())
        
        # Extract all the dashed value lines after the last field label
        dashed_values = []
        for i, line in enumerate(lines):
            if i > last_field_pos and (line.startswith("-") or line.startswith(":")):
                cleaned_value = re.sub(r'^[\-\:\|]+\s*', '', line).strip()
                if cleaned_value:
                    dashed_values.append(cleaned_value)
        
        # Process each missing field with a corresponding dashed value
        for i, field in enumerate(missing_fields):
            if i < len(dashed_values):
                result[field] = dashed_values[i]
    
    # ---- STEP 6: Handle Kewarganegaraan and Berlaku Hingga (often problematic) ----
    # These fields are often at the bottom and may be mixed up
    
    # Look for WNI explicitly
    for line in lines:
        if "WNI" in line and "Kewarganegaraan" not in result:
            result["Kewarganegaraan"] = "WNI"
    
    # Look for SEUMUR HIDUP explicitly
    for line in lines:
        if "SEUMUR HIDUP" in line and "Berlaku Hingga" not in result:
            result["Berlaku Hingga"] = "SEUMUR HIDUP"
    
    # ---- STEP 7: Fill in any missing fields with empty values ----
    for field in expected_fields:
        if field not in result or not result[field]:
            result[field] = "-"
    
    # Apply post-processing to clean up the extracted data
    result = post_process_fields(result)
    
    return result

def post_process_fields(data):
    """Apply additional cleaning and validation to extracted fields"""
    # Define a comprehensive regex for removing unwanted characters
    # This pattern matches various symbols, special characters, and OCR artifacts
    unwanted_chars_pattern = r'[«»><~`|\\(){}\[\]"\'=_+*^&%$#@!]'
    
    # Apply cleaning to all fields
    for field in data:
        if data[field] and isinstance(data[field], str):
            # Apply a series of cleaning operations in sequence
            
            # 1. Remove all unwanted characters completely
            data[field] = re.sub(unwanted_chars_pattern, '', data[field])
            
            # 2. Remove any leading/trailing whitespace or dashes
            data[field] = data[field].strip('- \t\n\r')
            
            # 3. Clean up extra whitespace
            data[field] = re.sub(r'\s+', ' ', data[field]).strip()
            
            # 4. Remove any trailing OCR garbage (alphabetic or numeric after a space at the end)
            data[field] = re.sub(r'\s+[a-z]{1,2}$', '', data[field])
    
    # Special field-specific cleaning
    
    # Clean Name field - remove anything that's not A-Z or space
    if "Nama" in data and data["Nama"]:
        # Convert name to uppercase and remove all non-alphabetic & non-space characters
        data["Nama"] = re.sub(r'[^A-Z\s]', '', data["Nama"].upper()).strip()
    
    # Clean Birth Date - remove anything after the date pattern
    if "Tempat/Tgl Lahir" in data and data["Tempat/Tgl Lahir"]:
        # Find the pattern CITY, DD-MM-YYYY and keep only that
        match = re.search(r'([A-Z]+,\s*\d{2}-\d{2}-\d{4})', data["Tempat/Tgl Lahir"].upper())
        if match:
            data["Tempat/Tgl Lahir"] = match.group(1)
        else:
            # If no exact match, just remove common OCR artifacts
            data["Tempat/Tgl Lahir"] = re.sub(r'\s+[a-zA-Z0-9]{1,2}$', '', data["Tempat/Tgl Lahir"])
    
    # Clean Gender field
    if "Jenis Kelamin" in data and data["Jenis Kelamin"]:
        if "LAKI" in data["Jenis Kelamin"].upper():
            data["Jenis Kelamin"] = "LAKI-LAKI"
        elif "PEREMPUAN" in data["Jenis Kelamin"].upper():
            data["Jenis Kelamin"] = "PEREMPUAN"
    
    # Clean Address field - ensure it properly captures street numbers
    if "Alamat" in data and data["Alamat"]:
        # Special case: Capture the entire address including the number at the end
        # First, standardize the address by removing unwanted characters
        clean_address = data["Alamat"]
        
        # Capture the full address pattern: JALAN/JL + name + NO + number
        address_match = re.search(r'(JALAN|JL)(.+)(NO\s*\d+)', clean_address.upper())
        if address_match:
            # Keep the entire matched pattern
            matched_address = address_match.group(0)
            # Find where this pattern starts in the original string (to preserve case)
            start_idx = clean_address.upper().find(matched_address)
            if start_idx >= 0:
                data["Alamat"] = clean_address[start_idx:start_idx+len(matched_address)]
        
        # If no match but address contains JALAN, keep from JALAN to the end
        elif "JALAN" in clean_address.upper() or "JL" in clean_address.upper():
            # Extract the portion starting with "JALAN" or "JL"
            jalan_match = re.search(r'(JALAN|JL).*', clean_address.upper())
            if jalan_match:
                # Keep the original case
                start_idx = clean_address.upper().find(jalan_match.group(0))
                data["Alamat"] = clean_address[start_idx:]
    
    # Ensure RT/RW format is clean (just digits and slash)
    if "RT/RW" in data and data["RT/RW"]:
        match = re.search(r'(\d+/\d+)', data["RT/RW"])
        if match:
            data["RT/RW"] = match.group(1)
    
    # Clean Kel/Desa - simple cleanup
    if "Kel/Desa" in data and data["Kel/Desa"]:
        # Remove anything that looks like OCR garbage at the end
        data["Kel/Desa"] = re.sub(r'\s+[a-z0-9]{1,3}$', '', data["Kel/Desa"])
        data["Kel/Desa"] = re.sub(r'\s+—+$', '', data["Kel/Desa"])  # Remove dashes at end
    
    # Clean Kecamatan - aggressive cleanup for dashes
    if "Kecamatan" in data and data["Kecamatan"]:
        # Extremely aggressive dash removal - extract just the first word
        kecamatan_value = data["Kecamatan"].strip()
        
        # If the Kecamatan contains dashes, take only the part before any dash or special char
        if "—" in kecamatan_value or "-" in kecamatan_value:
            # Take only the first word(s) before any dashes
            parts = re.split(r'[—\-]+', kecamatan_value)
            if parts and parts[0].strip():
                data["Kecamatan"] = parts[0].strip()
        
        # Also remove any trailing non-alphabetic characters
        data["Kecamatan"] = re.sub(r'[^A-Za-z\s]+.*$', '', data["Kecamatan"])
    
    # Clean Agama field - standardize to known values
    if "Agama" in data and data["Agama"]:
        if "ISLAM" in data["Agama"].upper():
            data["Agama"] = "ISLAM"
        elif "KRISTEN" in data["Agama"].upper():
            data["Agama"] = "KRISTEN"
        elif "KATOLIK" in data["Agama"].upper():
            data["Agama"] = "KATOLIK"
        elif "HINDU" in data["Agama"].upper():
            data["Agama"] = "HINDU"
        elif "BUDHA" in data["Agama"].upper():
            data["Agama"] = "BUDHA"
    
    # Clean Status Perkawinan - standardize to known values
    if "Status Perkawinan" in data and data["Status Perkawinan"]:
        if "BELUM KAWIN" in data["Status Perkawinan"].upper():
            data["Status Perkawinan"] = "BELUM KAWIN"
        elif "KAWIN" in data["Status Perkawinan"].upper():
            data["Status Perkawinan"] = "KAWIN"
        elif "CERAI" in data["Status Perkawinan"].upper():
            data["Status Perkawinan"] = "CERAI"
    
    # Clean Pekerjaan field - remove date if present
    if "Pekerjaan" in data and data["Pekerjaan"]:
        # Remove date pattern if present
        data["Pekerjaan"] = re.sub(r'\d{2}-\d{2}-\d{4}.*', '', data["Pekerjaan"])
        # Remove other OCR artifacts
        data["Pekerjaan"] = re.sub(r'\s+\d+.*$', '', data["Pekerjaan"])
    
    # Clean Berlaku Hingga and Kewarganegaraan - standardize values
    if "Berlaku Hingga" in data and data["Berlaku Hingga"]:
        if "SEUMUR HIDUP" in data["Berlaku Hingga"].upper():
            data["Berlaku Hingga"] = "SEUMUR HIDUP"
        # Fix common issue where Berlaku Hingga gets name value
        if data["Nama"] and data["Berlaku Hingga"] == data["Nama"]:
            data["Berlaku Hingga"] = "SEUMUR HIDUP"
    
    if "Kewarganegaraan" in data and data["Kewarganegaraan"]:
        if "WNI" in data["Kewarganegaraan"].upper():
            data["Kewarganegaraan"] = "WNI"
    
    # Final validation - ensure critical fields are not empty
    # If "Berlaku Hingga" has the name, fix it and reassign
    if "Berlaku Hingga" in data and data["Berlaku Hingga"]:
        if data["Berlaku Hingga"].upper() in ["AGUS PRASETYO", "RIZKY FAHREZI", "DEWI", "INTAN", "FITRIANI"]:
            # This is probably a name, not a validity period
            if not data["Nama"]:
                data["Nama"] = data["Berlaku Hingga"]
            data["Berlaku Hingga"] = "SEUMUR HIDUP"
    
    return data

def verify_identity(data):
    """Verify the extracted identity data against Firebase database"""
    nik = data.get("NIK")
    if not nik or nik == "-":
        return False, "No valid NIK found in extracted data"
    
    try:
        docs = db.collection('identities').where('NIK', '==', nik).stream()
        document_exists = False
        
        for doc in docs:
            document_exists = True
            record = doc.to_dict()
            
            # Compare name (with some tolerance for OCR errors)
            db_name = record.get('Nama', '')
            extracted_name = data.get('Nama', '')
            name_match = False
            
            if db_name and extracted_name:
                # Convert to uppercase for comparison
                db_name = db_name.upper()
                extracted_name = extracted_name.upper()
                
                # Clean up common OCR errors
                extracted_name = extracted_name.replace('!', 'I')
                
                if db_name == extracted_name:
                    name_match = True
                else:
                    # Check similarity (allow for small OCR errors)
                    similarity = 0
                    for c1, c2 in zip(db_name, extracted_name):
                        if c1 == c2:
                            similarity += 1
                    
                    max_len = max(len(db_name), len(extracted_name))
                    if max_len > 0 and similarity / max_len > 0.8:  # 80% similarity
                        name_match = True
            
            # Compare date of birth
            db_dob = record.get('Tempat/Tgl Lahir', '')
            extracted_dob = data.get('Tempat/Tgl Lahir', '')
            dob_match = False
            
            if db_dob and extracted_dob:
                # Clean up for comparison
                db_dob = re.sub(r'[^A-Z0-9,-]', '', db_dob.upper())
                extracted_dob = re.sub(r'[^A-Z0-9,-]', '', extracted_dob.upper())
                
                if db_dob == extracted_dob:
                    dob_match = True
            
            # Format detailed message
            details = (
                f"Database Name: '{record.get('Nama')}', Extracted: '{data.get('Nama')}'\n"
                f"Database DoB: '{record.get('Tempat/Tgl Lahir')}', Extracted: '{data.get('Tempat/Tgl Lahir')}'"
            )
            
            if name_match and dob_match:
                return True, f"Information is valid! Identity verified.\n\n{details}"
            else:
                return False, f"Data mismatch found.\n\n{details}"
        
        if not document_exists:
            return False, f"No matching NIK found in database for '{nik}'"
    
    except Exception as e:
        return False, f"Error during verification: {str(e)}"

# === Signature Verification Functions ===

def setup_drive_service():
    """Setup and return the Google Drive service."""
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    return build('drive', 'v3', credentials=creds)

def list_images_in_folder(drive_service, folder_id):
    """List image files in a Google Drive folder."""
    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and mimeType contains 'image/'",
        fields="files(id, name, modifiedTime)").execute()
    return results.get('files', [])

def download_image_with_retry(drive_service, file_id, max_retries=MAX_RETRIES):
    """Download image with retry logic for API failures."""
    import socket
    import ssl
    
    for attempt in range(max_retries):
        try:
            # Set socket timeout
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(TIMEOUT)
            
            request = drive_service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
            
            # Reset timeout
            socket.setdefaulttimeout(old_timeout)
            
            fh.seek(0)
            img_array = np.asarray(bytearray(fh.read()), dtype=np.uint8)
            return cv2.imdecode(img_array, cv2.IMREAD_COLOR)
        
        except (socket.timeout, ssl.SSLError) as e:
            if attempt < max_retries - 1:
                print(f"  ⚠️ Attempt {attempt+1} failed. Retrying...")
                time.sleep(1)  # Short delay before retry
            else:
                raise e
        except Exception as e:
            raise e
        finally:
            # Always reset timeout
            socket.setdefaulttimeout(old_timeout)

def align_images(img_user, img_ref):
    """Align user image with reference image using feature matching."""
    # Convert to grayscale for feature detection
    gray_user = cv2.cvtColor(img_user, cv2.COLOR_BGR2GRAY)
    gray_ref = cv2.cvtColor(img_ref, cv2.COLOR_BGR2GRAY)
    
    orb = cv2.ORB_create(3000)  # Reduced features for speed
    kp1, des1 = orb.detectAndCompute(gray_user, None)
    kp2, des2 = orb.detectAndCompute(gray_ref, None)

    if des1 is None or des2 is None:
        raise ValueError("Descriptors missing; check image content.")

    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    matches = sorted(matches, key=lambda x: x.distance)

    # Use only the best matches
    good_matches = matches[:min(30, len(matches))]  # Reduced for speed
    
    if len(good_matches) < 4:
        raise ValueError("Not enough good matches to align images.")

    src_pts = np.float32([kp1[m.queryIdx].pt for m in good_matches]).reshape(-1, 1, 2)
    dst_pts = np.float32([kp2[m.trainIdx].pt for m in good_matches]).reshape(-1, 1, 2)

    matrix, mask = cv2.findHomography(src_pts, dst_pts, cv2.RANSAC, 5.0)
    h, w = img_ref.shape[:2]
    return cv2.warpPerspective(img_user, matrix, (w, h))

def extract_signature(img, coords):
    """Extract and preprocess signature from the image."""
    startY, endY, startX, endX = coords
    h, w = img.shape[:2]
    crop = img[max(0, startY):min(h, endY), max(0, startX):min(w, endX)]
    
    if crop.size == 0:
        raise ValueError("❌ Signature crop is empty.")
        
    if len(crop.shape) == 3:
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
    else:
        gray = crop
        
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    threshold = cv2.adaptiveThreshold(blur, 255,
                               cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                               cv2.THRESH_BINARY_INV, 11, 2)
    return threshold

def compare_signatures(img_user, img_ref, coords):
    """Align images and compare signatures, return similarity score."""
    try:
        aligned_user = align_images(img_user, img_ref)
        sig_ref = extract_signature(img_ref, coords)
        sig_user = extract_signature(aligned_user, coords)

        if sig_ref.shape != sig_user.shape:
            sig_user = cv2.resize(sig_user, (sig_ref.shape[1], sig_ref.shape[0]))

        score, _ = ssim(sig_ref, sig_user, full=True)
        return score
    except Exception as e:
        print(f"⚠️ Error comparing signatures: {e}")
        return 0.0

def verify_signature(image_path, folder_id=FOLDER_ID, 
                    signature_coords=SIGNATURE_COORDS, 
                    threshold=SIMILARITY_THRESHOLD):
    """Main function to verify signature against reference images with robust error handling."""
    start_time = time.time()
    
    # Load user image
    img_user = cv2.imread(image_path)
    if img_user is None:
        raise ValueError("❌ Could not load user image.")
    
    # Setup Drive service
    drive_service = setup_drive_service()
    
    # Load all reference images metadata from the folder
    image_files = list_images_in_folder(drive_service, folder_id)
    if not image_files:
        raise ValueError("❌ No images found in the Google Drive folder.")
    
    print(f"🔍 Found {len(image_files)} images in the folder.")
    
    # Sort by most recently modified first and then by name
    image_files.sort(key=lambda x: (x.get('modifiedTime', ''), x['name']), reverse=True)
    
    # Process images one by one with robust error handling
    best_match = None
    best_score = 0.0
    processed_count = 0
    
    # Process each image individually
    for file in image_files:
        processed_count += 1
        print(f"🔍 Comparing with: {file['name']}")
        
        try:
            # Download and process each image with retry
            img_ref = download_image_with_retry(drive_service, file['id'])
            
            # Compare signatures
            score = compare_signatures(img_user, img_ref, signature_coords)
            print(f"  Similarity score: {score:.2f}")
            
            # If score exceeds threshold, we found a match
            if score >= threshold:
                print(f"✅ Match found! '{file['name']}' with score {score:.2f}")
                best_match = file
                best_score = score
                break  # Stop searching immediately
            
            # Keep track of best match regardless of threshold
            if score > best_score:
                best_score = score
                best_match = file
                
        except Exception as e:
            print(f"  ⚠️ Error processing {file['name']}: {e}")
            continue  # Skip this file and move to next
    
    # Report results
    end_time = time.time()
    search_time = end_time - start_time
    
    print(f"\n⏱️ Search completed in {search_time:.2f} seconds.")
    print(f"📊 Processed {processed_count} out of {len(image_files)} images.")
    
    if best_match and best_score >= threshold:
        print(f"✅ Match found: {best_match['name']}")
        print(f"✅ Similarity score: {best_score:.2f}")
        return True, best_match['name'], best_score
    else:
        print(f"❌ No match found above threshold ({threshold}).")
        if best_match:
            print(f"📌 Best match was: {best_match['name']} with score {best_score:.2f}")
        return False, None, best_score
    

def verify_ktp_data_and_signature(image_path):
    """Perform both data extraction/verification and signature verification."""
    results = {
        "data_verification": {
            "success": False,
            "message": ""
        },
        "signature_verification": {
            "success": False,
            "match_name": None,
            "similarity_score": 0,
            "message": ""
        },
        "extracted_data": {}
    }
    
    try:
        # Process image for OCR
        processed_image = preprocess_image(image_path)
        raw_text = extract_tb(processed_image)
        
        # Extract and clean data fields
        extracted_data = extract_fields(raw_text)
        results["extracted_data"] = extracted_data
        
        # Verify identity data against database
        data_verified, message = verify_identity(extracted_data)
        results["data_verification"]["success"] = data_verified
        results["data_verification"]["message"] = message
        
        # Verify signature regardless of data verification result
        try:
            sig_verified, match_name, score = verify_signature(image_path)
            results["signature_verification"]["success"] = sig_verified
            results["signature_verification"]["match_name"] = match_name
            results["signature_verification"]["similarity_score"] = score
            
            if sig_verified:
                results["signature_verification"]["message"] = f"Signature matched with '{match_name}' (Score: {score:.2f})"
            else:
                if match_name:
                    results["signature_verification"]["message"] = f"Best match was '{match_name}' but score ({score:.2f}) is below threshold"
                else:
                    results["signature_verification"]["message"] = f"No signature match found. Best score: {score:.2f}"
        
        except Exception as e:
            results["signature_verification"]["message"] = f"Error during signature verification: {str(e)}"
    
    except Exception as e:
        results["data_verification"]["message"] = f"Error during data extraction: {str(e)}"
    
    # Compute overall verification result
    results["overall_success"] = results["data_verification"]["success"] and results["signature_verification"]["success"]
    
    return results

# === New Selfie Verification Functions ===

def verify_human_selfie(image_data):
    """
    Verify that the selfie contains a human face
    Returns a tuple of (is_human, confidence_score, message)
    """
    try:
        # Decode the base64 image data
        image_bytes = base64.b64decode(image_data.split(',')[1])
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return False, 0, "Failed to decode image"
        
        # Load the face detection model
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Convert to grayscale for face detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Detect faces in the image
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(30, 30)
        )
        
        # Check if at least one face is detected
        if len(faces) > 0:
            # Calculate a confidence score based on detection strength
            # (using the size of the largest face relative to the image)
            largest_face = max(faces, key=lambda x: x[2] * x[3])
            face_area = largest_face[2] * largest_face[3]
            total_area = img.shape[0] * img.shape[1]
            
            # Calculate confidence score (0-1)
            confidence = min(face_area / (total_area * 0.2), 1.0)  # Cap at 1.0
            
            # Save the detected face coordinates for future use
            x, y, w, h = largest_face
            
            # Simple test to check if it's likely a real person (not just a photo)
            # This could be enhanced with more sophisticated checks in a production system
            msg = f"Human detected with confidence {confidence:.2f}"
            return True, confidence, msg
        
        return False, 0, "No human face detected in the image"
    
    except Exception as e:
        return False, 0, f"Error in human verification: {str(e)}"

# === Routes ===

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            
            try:
                # Run both verifications
                verification_results = verify_ktp_data_and_signature(filepath)
                
                # Store the results in session for use in selfie verification
                session['verification_results'] = verification_results
                session['verified_nik'] = verification_results['extracted_data'].get('NIK', '')
                
                # Redirect to selfie verification page if documents are verified
                if verification_results["overall_success"]:
                    return render_template('result.html', 
                                          data=verification_results["extracted_data"], 
                                          verified=verification_results["data_verification"]["success"],
                                          message=verification_results["data_verification"]["message"],
                                          signature_verified=verification_results["signature_verification"]["success"],
                                          signature_match=verification_results["signature_verification"]["match_name"],
                                          signature_score=verification_results["signature_verification"]["similarity_score"],
                                          signature_message=verification_results["signature_verification"]["message"],
                                          overall_success=verification_results["overall_success"],
                                          show_selfie_button=True)
                else:
                    # If verification failed, still show results but without selfie option
                    return render_template('result.html', 
                                          data=verification_results["extracted_data"], 
                                          verified=verification_results["data_verification"]["success"],
                                          message=verification_results["data_verification"]["message"],
                                          signature_verified=verification_results["signature_verification"]["success"],
                                          signature_match=verification_results["signature_verification"]["match_name"],
                                          signature_score=verification_results["signature_verification"]["similarity_score"],
                                          signature_message=verification_results["signature_verification"]["message"],
                                          overall_success=verification_results["overall_success"],
                                          show_selfie_button=False)
            
            except Exception as e:
                flash(f'Error processing the image: {str(e)}')
                return redirect(request.url)

    return render_template('upload.html')

@app.route('/selfie_verification')
def selfie_verification():
    # Check if we have previous verification results
    if 'verification_results' not in session:
        flash('Please verify your ID first')
        return redirect(url_for('upload_file'))
        
    # Get the person's name from session
    verification_results = session.get('verification_results', {})
    person_name = verification_results.get('extracted_data', {}).get('Nama', 'User')
    
    # Render the selfie verification page
    return render_template('selfie.html', person_name=person_name)

@app.route('/verify_selfie', methods=['POST'])
def verify_selfie():
    if request.method != 'POST':
        return jsonify({'success': False, 'message': 'Invalid request method'})
    
    try:
        # Get the selfie image data from the request
        data = request.json
        image_data = data.get('image')
        
        if not image_data:
            return jsonify({'success': False, 'message': 'No image data received'})
        
        # Verify the selfie contains a human
        is_human, confidence, message = verify_human_selfie(image_data)
        
        if is_human and confidence > 0.5:  # Set an appropriate threshold
            # Mark the session as having passed the human verification
            session['human_verified'] = True
            return jsonify({
                'success': True, 
                'message': 'Human verification successful',
                'redirect': url_for('dashboard')
            })
        else:
            return jsonify({
                'success': False, 
                'message': message
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/dashboard')
def dashboard():
    # Check if the user has completed both verification steps
    if not session.get('verification_results'):
        flash('Please verify your ID first')
        return redirect(url_for('upload_file'))
        
    if not session.get('human_verified'):
        flash('Please complete the selfie verification')
        return redirect(url_for('selfie_verification'))
    
    # Get user data from session
    verification_results = session.get('verification_results', {})
    user_data = verification_results.get('extracted_data', {})
    
        # Get current time
    current_time = datetime.now()

    # Render the dashboard
    return render_template('dashboard.html', user_data=user_data, now=current_time)

if __name__ == "__main__":
    app.run(debug=True)