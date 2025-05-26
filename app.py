import os
import base64
import hashlib
import json
import io
import tempfile
import uuid
import traceback
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from flask import Flask, flash, request, jsonify, send_file, render_template, url_for, redirect, session
from werkzeug.utils import secure_filename
from verification import verify_ktp_data_and_signature, verify_human_selfie

# PDF manipulation imports
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from PIL import Image
import fitz  # PyMuPDF - alternative PDF library for better image handling

# Firebase imports
import firebase_admin
from firebase_admin import credentials, firestore, storage, auth
import pyrebase

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='securesign.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = "uploads"
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB limit

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Firebase Admin SDK
cred = credentials.Certificate("securesign-firebase-key.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'securesign-app.appspot.com'
})
db = firestore.client()

# Initialize Pyrebase for auth
firebase_config = {
    "apiKey": "AIzaSyAze5hQDqpuUuD0E5bwpwJUj_yd9AWTH8U",
    "authDomain": "securesign-app.firebaseapp.com",
    "projectId": "securesign-app",
    "storageBucket": "securesign-app.appspot.com",
    "messagingSenderId": "123456789012",
    "appId": "1:123456789012:web:123456789012",
    "databaseURL": ""
}
firebase = pyrebase.initialize_app(firebase_config)
auth_instance = firebase.auth()

class DocumentEncryptor:
    def __init__(self):
        self.backend = default_backend()
    
    def _derive_key_from_password(self, password, salt=None):
        """Generate a key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        # Generate a 256-bit key
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # Number of iterations
            32  # Key length
        )
        
        return key, salt
    
    def encrypt_document(self, file_data, password):
        """Encrypt document data with password"""
        try:
            # Generate key from password
            key, salt = self._derive_key_from_password(password)
            
            # Generate random IV (Initialization Vector)
            iv = os.urandom(16)
            
            # Create AES-CBC cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Apply padding to ensure the data is a multiple of the block size
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(file_data) + padder.finalize()
            
            # Encrypt the data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepare metadata
            metadata = {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8')
            }
            
            # Convert encrypted data to base64 for Firebase storage
            encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            
            return encrypted_base64, metadata
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise Exception(f"Failed to encrypt document: {str(e)}")
    
    def decrypt_document(self, encrypted_base64, password, metadata):
        """Decrypt document data with password"""
        try:
            # Extract salt and IV from metadata
            salt = base64.b64decode(metadata["salt"])
            iv = base64.b64decode(metadata["iv"])
            
            # Derive the same key using the provided password and salt
            key, _ = self._derive_key_from_password(password, salt)
            
            # Create AES-CBC cipher for decryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Decode base64 encrypted data
            encrypted_data = base64.b64decode(encrypted_base64)
            
            # Decrypt the data
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise ValueError("Invalid password or corrupted document")

class DocumentManager:
    def __init__(self):
        self.encryptor = DocumentEncryptor()
        self.bucket = storage.bucket()
    
    def process_document_upload(self, file_data, filename, user_id, password, placeholder_positions):
        """Process document upload and encrypt it"""
        try:
            # Generate a unique document ID
            document_id = str(uuid.uuid4())
            logger.info(f"Processing new document upload, assigned ID: {document_id}")
            
            # Encrypt the document
            encrypted_base64, encryption_metadata = self.encryptor.encrypt_document(file_data, password)
            
            # Ensure placeholder positions are using absolute pixel values
            # This is crucial for consistent positioning across pages
            normalized_placeholders = []
            for placeholder in placeholder_positions:
                # Log the placeholder details for debugging
                logger.info(f"Processing placeholder: {placeholder}")
                
                normalized_placeholder = {
                    'id': placeholder.get('id', len(normalized_placeholders) + 1),
                    'page': placeholder.get('page', 1),
                    'x': float(placeholder.get('x', 0)),  # Store as absolute pixel values
                    'y': float(placeholder.get('y', 0)),  # Store as absolute pixel values
                    'width': float(placeholder.get('width', 200)),  # Store width in pixels
                    'height': float(placeholder.get('height', 70)),  # Store height in pixels
                    'recipientEmail': placeholder.get('recipientEmail', '').strip().lower()  # Ensure email is standardized
                }
                
                # Log normalized placeholder to verify the email is being saved
                logger.info(f"Normalized placeholder: {normalized_placeholder}")
                
                normalized_placeholders.append(normalized_placeholder)
            
            # Generate a document hash for future verification
            document_hash = hashlib.sha256(file_data).hexdigest()

            # Create metadata
            document_metadata = {
                "document_id": document_id,
                "document_hash": document_hash,  # New field
                "encryption_metadata": encryption_metadata,
                "created_at": datetime.now().isoformat(),
                "status": "pending_signature",
                "placeholder_positions": normalized_placeholders,  # Use normalized placeholders
                "original_filename": filename,
                "uploaded_by": user_id,
                "signatures": {},  # Initialize empty signatures object
                "file_type": self._get_file_type(filename)
            }
            
            # Split the base64 data into chunks if it's too large for Firestore
            chunks = self._split_into_chunks(encrypted_base64)
            
            # Create document entry in Firestore
            doc_ref = db.collection('documents').document(document_id)
            doc_ref.set(document_metadata)
            
            # Store chunks in document_chunks collection
            for i, chunk in enumerate(chunks):
                chunk_doc = {
                    "document_id": document_id,
                    "chunk_index": i,
                    "total_chunks": len(chunks),
                    "data": chunk
                }
                db.collection('document_chunks').document(f"{document_id}_chunk_{i}").set(chunk_doc)
            
            logger.info(f"Document upload processed successfully: {document_id}")
            return document_id
        except Exception as e:
            logger.error(f"Document upload processing error: {str(e)}")
            logger.error(traceback.format_exc())
            raise Exception(f"Failed to process document upload: {str(e)}")
    
    def _split_into_chunks(self, base64_data, chunk_size=900000):
        """Split base64 data into chunks to avoid Firestore 1MB limit"""
        return [base64_data[i:i+chunk_size] for i in range(0, len(base64_data), chunk_size)]
    
    def _get_file_type(self, filename):
        """Determine file type from filename"""
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.pdf':
            return 'application/pdf'
        elif ext in ['.doc', '.docx']:
            return 'application/msword'
        elif ext in ['.xls', '.xlsx']:
            return 'application/vnd.ms-excel'
        elif ext in ['.jpg', '.jpeg']:
            return 'image/jpeg'
        elif ext == '.png':
            return 'image/png'
        else:
            return 'application/octet-stream'
    
    def get_document_info(self, document_id, password):
            """Get document info (placeholders) without decrypting the full document"""
            try:
                # Get document metadata from Firestore
                doc_ref = db.collection('documents').document(document_id)
                doc = doc_ref.get()
                
                if not doc.exists:
                    logger.error(f"Document ID {document_id} not found")
                    raise ValueError(f"Document ID {document_id} not found")
                
                document_data = doc.to_dict()
                
                # Verify password by attempting to create decryption key
                if 'encryption_metadata' in document_data:
                    encryption_metadata = document_data['encryption_metadata']
                    salt = base64.b64decode(encryption_metadata["salt"])
                    self.encryptor._derive_key_from_password(password, salt)
                else:
                    logger.error(f"Encryption metadata not found for document {document_id}")
                    raise ValueError("Encryption metadata not found")
                
                # Extract placeholder positions and ensure proper naming for frontend consistency
                placeholder_positions = document_data.get('placeholder_positions', [])
                signatures = document_data.get('signatures', {})
                
                # Return document info - ensure we use 'placeholders' key for frontend consistency
                return {
                    "document_id": document_id,
                    "original_filename": document_data.get("original_filename", "document.pdf"),
                    "status": document_data.get("status", "pending_signature"),
                    "created_at": document_data.get("created_at"),
                    "signed_at": document_data.get("signed_at"),
                    "placeholders": placeholder_positions,  # Use consistent naming
                    "signatures": signatures
                }
            except ValueError as e:
                logger.error(f"Value error getting document info: {str(e)}")
                raise
            except Exception as e:
                logger.error(f"Error getting document info: {str(e)}")
                raise ValueError(f"Failed to get document info: {str(e)}")
    
    def retrieve_document(self, document_id, password):
        """Retrieve and decrypt document"""
        try:
            # Get document metadata from Firestore
            doc_ref = db.collection('documents').document(document_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                logger.error(f"Document ID {document_id} not found")
                raise ValueError(f"Document ID {document_id} not found")
            
            document_data = doc.to_dict()
            
            # Extract encryption metadata
            encryption_metadata = document_data.get('encryption_metadata', {})
            if not encryption_metadata:
                logger.error(f"Encryption metadata not found for document {document_id}")
                raise ValueError("Encryption metadata not found")
            
            # Get all chunks for this document from Firestore
            chunks_query = db.collection('document_chunks').where('document_id', '==', document_id).order_by('chunk_index').stream()
            
            chunks = []
            for chunk_doc in chunks_query:
                chunks.append(chunk_doc.to_dict().get('data', ''))
            
            if not chunks:
                logger.error(f"No chunks found for document {document_id}")
                raise ValueError("Document data not found")
            
            # Combine chunks to get complete encrypted data
            encrypted_base64 = ''.join(chunks)
            
            # Decrypt the document
            decrypted_data = self.encryptor.decrypt_document(encrypted_base64, password, encryption_metadata)
            
            # # If signatures exist, embed them in the PDF
            # if document_data.get('signatures'):
            #     placeholders = document_data.get('placeholder_positions', [])
            #     signatures = document_data.get('signatures', {})
            #     decrypted_data = PDFSignatureEmbedder.embed_signatures_in_pdf(decrypted_data, placeholders, signatures)
            
            original_filename = document_data.get('original_filename', 'document.pdf')
            
            return decrypted_data, original_filename, document_data
        except ValueError as e:
            logger.error(f"Value error retrieving document: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error retrieving document: {str(e)}")
            raise ValueError(f"Failed to retrieve document: {str(e)}")
    
    def save_signed_document(self, document_id, password, new_signatures):
        """Save document with signatures"""
        try:
            # Get document metadata from Firestore
            doc_ref = db.collection('documents').document(document_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                logger.error(f"Document ID {document_id} not found")
                raise ValueError(f"Document ID {document_id} not found")
            
            document_data = doc.to_dict()
            
            # Extract encryption metadata
            encryption_metadata = document_data.get('encryption_metadata', {})
            if not encryption_metadata:
                logger.error(f"Encryption metadata not found for document {document_id}")
                raise ValueError("Encryption metadata not found")
            
            # Get existing signatures and merge with new ones
            existing_signatures = document_data.get('signatures', {})
            all_signatures = {**existing_signatures, **new_signatures}
            
            # Update Firestore document with signatures
            doc_ref.update({
                'signatures': all_signatures,
                'updated_at': datetime.now().isoformat()
            })
            
            # Update document status only if all placeholders are signed
            all_signed = True
            placeholder_positions = document_data.get('placeholder_positions', [])
            
            for placeholder in placeholder_positions:
                if str(placeholder['id']) not in all_signatures:
                    all_signed = False
                    break
                    
            if all_signed:
                doc_ref.update({
                    'status': 'signed',
                    'signed_at': datetime.now().isoformat()
                })
            
            logger.info(f"Successfully saved signatures for document {document_id}")
            return {
                "status": "success", 
                "message": "Document signatures saved successfully",
                "all_signed": all_signed
            }
        except ValueError as e:
            logger.error(f"Value error saving signed document: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error saving signed document: {str(e)}")
            logger.error(traceback.format_exc())
            raise ValueError(f"Failed to save signed document: {str(e)}")
    
    def delete_document(self, document_id, user_id):
        """Delete a document and its chunks"""
        try:
            # Get document metadata from Firestore
            doc_ref = db.collection('documents').document(document_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                logger.error(f"Document ID {document_id} not found")
                raise ValueError(f"Document ID {document_id} not found")
                
            document_data = doc.to_dict()
            
            # Verify user is the owner
            if document_data.get('uploaded_by') != user_id:
                logger.error(f"User {user_id} attempted to delete document {document_id} but is not the owner")
                raise ValueError("You do not have permission to delete this document")
            
            # Delete all chunks
            chunks_query = db.collection('document_chunks').where('document_id', '==', document_id).stream()
            
            for chunk_doc in chunks_query:
                chunk_doc.reference.delete()
            
            # Delete main document
            doc_ref.delete()
            
            logger.info(f"Successfully deleted document {document_id}")
            return {"status": "success", "message": "Document deleted successfully"}
            
        except ValueError as e:
            logger.error(f"Value error deleting document: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error deleting document: {str(e)}")
            raise ValueError(f"Failed to delete document: {str(e)}")

def check_nik_availability(nik, current_user_id):
    """
    Check if a NIK is already used by another user
    Returns (is_available, user_email) tuple
    """
    users = db.collection('users').where('verified_nik', '==', nik).get()
    
    for user in users:
        user_data = user.to_dict()
        # If user ID doesn't match current user, NIK is already taken
        if user.id != current_user_id:
            return False, user_data.get('email', 'another user')
    
    # If we got here, NIK is available or belongs to current user
    return True, None

def send_invitation_email(recipient_email, signing_link, view_link):
    try:
        sender_email = "villager.cyber@gmail.com"
        app_password = "shfg fukb ofkh afkx"
        
        # Set up the MIME
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = 'Invitation to Sign Document'

        body = f"""Hello,

        You have been invited to sign a document. Please use the following link to sign it:
        {signing_link}

        Additionally, you can view the document using the following link:
        {view_link}

        Best regards,
        SecureSign Team"""
        
        msg.attach(MIMEText(body, 'plain'))

        # Setup the server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Encrypt the connection
        server.login(sender_email, app_password)
        
        # Send email
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        
        # Quit the server
        server.quit()
        
        print("Invitation email sent successfully!")
    
    except Exception as e:
        print(f"Error sending email: {str(e)}")

# Flask routes
@app.route('/api/test')
def test_api():
    """Test if the API is working"""
    return jsonify({
        "status": "success",
        "message": "API is working correctly"
    })

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login')
def login():
    """Login page"""
    return render_template('login.html')

@app.route('/signup')
def signup():
    """Signup page"""
    return render_template('signup.html')

# Add these routes to app.py without modifying existing upload route
@app.route('/verification')
def verification():
    """Verification page for user identity"""
    # Get redirect URL from query parameters
    redirect_url = request.args.get('redirect', '')
    
    # Pass the redirect URL to the template
    return render_template('upload_data.html', redirect_url=redirect_url)


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

    return render_template('upload_data.html')

@app.route('/selfie_verification')
def selfie_verification():
    # Check if we have previous verification results
    if 'verification_results' not in session:
        flash('Please verify your ID first')
        return redirect(url_for('verification'))
        
    # Get the person's name from session
    verification_results = session.get('verification_results', {})
    person_name = verification_results.get('extracted_data', {}).get('Nama', 'User')
    
    # Get redirect URL from multiple sources in priority order:
    # 1. Query parameter (from upload_data.html redirect)
    redirect_param = request.args.get('redirect', '')
    
    # 2. Session (from verify_identity)
    redirect_session = session.get('redirect_after_verification', '')
    
    # Use the first available redirect URL
    redirect_url = redirect_param or redirect_session or ''
    
    # Log the redirect URL for debugging
    logger.info(f"Selfie verification with redirect URL: {redirect_url}")
    
    # Render the selfie verification page with redirect URL
    return render_template('selfie.html', person_name=person_name, redirect_url=redirect_url)

@app.route('/verify_selfie', methods=['POST'])
def verify_selfie():
    if request.method != 'POST':
        return jsonify({'success': False, 'message': 'Invalid request method'})
    
    try:
        # Get the selfie image data from the request
        data = request.json
        image_data = data.get('image')
        user_id = data.get('userId')
        
        # Get redirect URL from multiple sources in priority order:
        # 1. Request JSON (from client-side JavaScript)
        redirect_json = data.get('redirectUrl', '')
        
        # 2. Session (from verify_identity)
        redirect_session = session.get('redirect_after_verification', '')
        
        # Use the best redirect URL available
        redirect_url = redirect_json or redirect_session or ''
        
        # Log the redirect URL for debugging
        logger.info(f"Verify selfie with redirect URL: {redirect_url}")
        
        if not image_data:
            return jsonify({'success': False, 'message': 'No image data received'})
        
        # Verify the selfie contains a human
        is_human, confidence, message = verify_human_selfie(image_data)
        
        if is_human and confidence > 0.5:
            # Mark the session as having passed the human verification
            session['human_verified'] = True
            
            # Get the verified NIK from session
            verified_nik = session.get('verified_nik')
            
            # Double check again that the NIK is still available for this user
            nik_available, existing_user = check_nik_availability(verified_nik, user_id)
            
            if not nik_available:
                return jsonify({
                    'success': False,
                    'message': f'This National ID (NIK) is now associated with another user. Please try again with a different ID.'
                })
            
            # Update user's verification status in Firebase
            if user_id:
                db.collection('users').document(user_id).update({
                    'verified': True,
                    'verification_completed': True,
                    'verificationDate': datetime.now().isoformat()
                })
            
            # Clear the session redirect URL as we're returning it in the response
            if 'redirect_after_verification' in session:
                session.pop('redirect_after_verification')
            
            # Determine where to redirect after successful verification
            # If we have a redirect URL, use it. Otherwise, default to dashboard.
            if redirect_url:
                logger.info(f"Redirecting after verification to: {redirect_url}")
                redirect_to = redirect_url
            else:
                logger.info("No redirect URL found, using dashboard as default")
                redirect_to = url_for('dashboard')
            
            return jsonify({
                'success': True, 
                'message': 'Human verification successful',
                'redirect': redirect_to
            })
        else:
            return jsonify({
                'success': False, 
                'message': message
            })
            
    except Exception as e:
        logger.error(f"Error in verify_selfie: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/verify_identity', methods=['POST'])
def verify_identity():
    try:
        data = request.json
        nama = data.get('nama')
        nik = data.get('nik')
        user_id = data.get('userId')
        redirect_url = data.get('redirectUrl')  # Get redirect URL from request
        
        if not nama or not nik or not user_id:
            return jsonify({'success': False, 'message': 'Missing required information'}), 400
        
        # First, check if this NIK is already associated with another user
        nik_available, existing_user = check_nik_availability(nik, user_id)
        
        if not nik_available:
            return jsonify({
                'success': False, 
                'message': f'This National ID (NIK) is already associated with another user. Each ID can only be used for one account.'
            }), 400
        
        # Check against identities collection
        identity_docs = db.collection('identities').where('NIK', '==', nik).get()
        
        identity_verified = False
        for doc in identity_docs:
            identity_data = doc.to_dict()
            if identity_data.get('Nama', '').upper() == nama.upper():
                identity_verified = True
                break
        
        if not identity_verified:
            return jsonify({'success': False, 'message': 'Identity not found or name does not match. Please check your information.'}), 400
        
        # Store verification data in session
        verification_results = {
            "data_verification": {
                "success": True,
                "message": "Identity verified successfully"
            },
            "extracted_data": {
                "NIK": nik,
                "Nama": nama
            },
            "overall_success": True
        }
        
        session['verification_results'] = verification_results
        session['verified_nik'] = nik
        
        # Store the verified NIK in the user's document
        db.collection('users').document(user_id).update({
            'verified_nik': nik,
            'verified_name': nama,
            'verification_started': True,
            'verification_start_time': datetime.now().isoformat()
        })
        
        # Also store the redirect URL in session if provided
        if redirect_url:
            session['redirect_after_verification'] = redirect_url
        
        return jsonify({'success': True, 'message': 'Identity verified successfully'})
        
    except Exception as e:
        logger.error(f"Error verifying identity: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/dashboard')
def dashboard():
    """Dashboard page - only accessible after verification"""
    # Get user ID from session or request
    user_id = session.get('user_id') or request.args.get('user_id')
    
    if not user_id:
        # If no user ID in session, try to get from localStorage via JavaScript redirect
        return render_template('check_auth.html', redirect_url='/verification')
    
    # Check if the user is verified
    try:
        user_doc = db.collection('users').document(user_id).get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            if not user_data.get('verified', False):
                # User is not verified, redirect to verification
                return redirect(url_for('verification'))
        else:
            # User document doesn't exist, redirect to login
            return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error checking user verification: {str(e)}")
        # On error, assume not verified
        return redirect(url_for('verification'))
    
    # User is verified, render dashboard
    return render_template('dashboard.html')

@app.route('/documents')
def document_list():
    """Document list page"""
    return render_template('document_list.html')

@app.route('/upload')
def upload_document():
    """Document upload page"""
    return render_template('upload.html')

@app.route('/upload-secure')
def upload_secure():
    """Enhanced document upload page"""
    return render_template('upload.html')

@app.route('/api/documents/user/<user_id>', methods=['GET'])
def get_user_documents(user_id):
    """Get documents for a user"""
    try:
        # Get documents uploaded by the user
        uploader_docs = db.collection('documents').where('uploaded_by', '==', user_id).stream()
        
        documents = []
        for doc in uploader_docs:
            doc_data = doc.to_dict()
            documents.append({
                'id': doc.id,
                'documentId': doc_data.get('document_id'),
                'fileName': doc_data.get('original_filename', 'Untitled'),
                'fileType': doc_data.get('file_type', 'application/pdf'),
                'status': doc_data.get('status', 'pending'),
                'createdAt': doc_data.get('created_at'),
                'updatedAt': doc_data.get('updated_at'),
                'signatories': doc_data.get('signatories', []),
                'uploadedBy': doc_data.get('uploaded_by')
            })
        
        return jsonify({
            "success": True,
            "documents": documents
        })
    except Exception as e:
        logger.error(f"Error getting user documents: {str(e)}")
        return jsonify({"error": f"Failed to get documents: {str(e)}"}), 500

@app.route('/api/upload', methods=['POST'])
def api_upload_document():
    try:
        logger.info("Document upload request received")
        
        if 'file' not in request.files:
            logger.warning("Upload request missing file part")
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.warning("Upload request has empty filename")
            return jsonify({"error": "No selected file"}), 400
        
        # Get password and placeholder positions from form
        password = request.form.get('password')
        if not password:
            logger.warning("Upload request missing password")
            return jsonify({"error": "Password is required"}), 400
        
        user_id = request.form.get('user_id', '')
        if not user_id:
            logger.warning("Upload request missing user ID")
            return jsonify({"error": "User ID is required"}), 400
        
        placeholder_data = request.form.get('placeholders', '[]')
        placeholder_positions = json.loads(placeholder_data)

        file_data = file.read()
        document_manager = DocumentManager()
        document_id = document_manager.process_document_upload(file_data, file.filename, user_id, password, placeholder_positions)
        
        # Generate links
        host = request.host_url.rstrip('/')
        signing_url = f"{host}/sign/{document_id}"
        view_url = f"{host}/document/{document_id}"
        
        # Send email to the recipient
        for placeholder in placeholder_positions:
            recipient_email = placeholder.get('recipientEmail')
            if recipient_email:
                send_invitation_email(recipient_email, signing_url, view_url)
        
        return jsonify({
            "status": "success",
            "document_id": document_id,
            "signing_url": signing_url,
            "view_url": view_url
        })

    except Exception as e:
        logger.error(f"Document upload failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/forgot-password')
def forgot_password():
    """Forgot password page"""
    return render_template('forgot_password.html')

@app.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    """Handle password reset request"""
    try:
        email = request.json.get('email')
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        # Send password reset email via Firebase
        auth_instance.send_password_reset_email(email)
        
        return jsonify({
            "success": True,
            "message": "Password reset email sent. Please check your inbox."
        })
        
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({"error": f"Failed to send password reset email: {str(e)}"}), 500
    
@app.route('/user/<user_id>', methods=['GET'])
def get_user_data(user_id):
    """Get user data from Firestore"""
    try:
        user_doc = db.collection('users').document(user_id).get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            return jsonify({
                "success": True,
                "userData": user_data
            })
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error(f"Error getting user data: {str(e)}")
        return jsonify({"error": f"Failed to get user data: {str(e)}"}), 500

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Handle user login with Firebase custom tokens"""
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
            
        # Use Pyrebase for authentication
        try:
            user = auth_instance.sign_in_with_email_and_password(email, password)
            
            # Get user details from Firestore
            user_doc = db.collection('users').document(user['localId']).get()
            user_data = {}
            is_verified = False
            
            if user_doc.exists:
                user_data = user_doc.to_dict()
                # Get verification status - checking both verified and verification_completed fields
                is_verified = user_data.get('verified', False) and user_data.get('verification_completed', False)
                
                return jsonify({
                    "success": True,
                    "userId": user['localId'],
                    "token": user['idToken'],
                    "userData": user_data,
                    "verified": is_verified
                })
            else:
                # Create a new user document if it doesn't exist
                user_data = {
                    "email": email,
                    "displayName": user.get('displayName', 'User'),
                    "createdAt": datetime.now().isoformat(),
                    "verified": False,
                    "verification_completed": False,
                    "role": "user"
                }
                db.collection('users').document(user['localId']).set(user_data)
                
                return jsonify({
                    "success": True,
                    "userId": user['localId'],
                    "token": user['idToken'],
                    "userData": user_data,
                    "verified": False
                })
                
        except Exception as e:
            logger.error(f"Login attempt failed for {email}: {str(e)}")
            return jsonify({"error": f"Login failed: {str(e)}"}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Server error during login"}), 500

@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    """Handle user signup"""
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        display_name = request.json.get('displayName')
        
        if not email or not password or not display_name:
            return jsonify({"error": "Email, password and display name are required"}), 400
            
        # Create user with Firebase Admin SDK
        try:
            user = auth.create_user(
                email=email,
                password=password,
                display_name=display_name
            )
            
            # Create user document in Firestore
            db.collection('users').document(user.uid).set({
                'uid': user.uid,
                'email': email,
                'displayName': display_name,
                'createdAt': datetime.now().isoformat(),
                'verified': False,
                'role': 'user'
            })
            
            # Create custom token for client-side auth
            custom_token = auth.create_custom_token(user.uid)
            
            return jsonify({
                "success": True,
                "userId": user.uid,
                "token": custom_token.decode('utf-8'),
                "message": "User created successfully"
            })
            
        except Exception as e:
            return jsonify({"error": f"Failed to create user: {str(e)}"}), 400
            
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({"error": "Server error during signup"}), 500

@app.route('/api/documents/<document_id>', methods=['DELETE'])
def api_delete_document(document_id):
    """Delete a document"""
    try:
        # Get user ID from request
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({"error": "User ID is required"}), 400
        
        # Delete document
        document_manager = DocumentManager()
        result = document_manager.delete_document(document_id, user_id)
        
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        logger.error(f"Error deleting document: {str(e)}")
        return jsonify({"error": f"Failed to delete document: {str(e)}"}), 500

@app.route('/api/verify', methods=['POST'])
def api_verify_document():
    """Verify a document's signatures"""
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "error": "No file selected"}), 400
            
        # Process the file
        file_data = file.read()
        
        # Generate document hash
        document_hash = hashlib.sha256(file_data).hexdigest()
        logger.info(f"Calculated hash for document verification: {document_hash}")
        
        # Get document ID if provided
        document_id = request.form.get('document_id')
        verification_code = request.form.get('verification_code')
        
        # Debug logging
        logger.info(f"Verification attempt with document_id: {document_id}, hash: {document_hash[:10]}..., verification_code: {verification_code}")
        
        # Search strategy: First by ID, then by hash, then by verification code
        document_found = None
        found_method = None
        
        # First check if document exists by ID
        if document_id:
            doc_ref = db.collection('documents').document(document_id)
            doc = doc_ref.get()
            if doc.exists:
                document_found = doc.to_dict()
                document_found['id'] = doc.id
                found_method = "by document ID"
                logger.info(f"Document found by ID: {document_id}")
        
        # If not found by ID, try to find by hash
        if not document_found:
            docs = db.collection('documents').where('document_hash', '==', document_hash).stream()
            for doc in docs:
                document_found = doc.to_dict()
                document_found['id'] = doc.id
                found_method = "by document hash"
                logger.info(f"Document found by hash: {doc.id}")
                break
        
        # If not found by hash, try to find by verification code (if provided)
        if not document_found and verification_code:
            docs = db.collection('documents').where('verification_code', '==', verification_code).stream()
            for doc in docs:
                document_found = doc.to_dict()
                document_found['id'] = doc.id
                found_method = "by verification code"
                logger.info(f"Document found by verification code: {doc.id}")
                break
        
        # If still not found, try to find by keywords including the verification code
        if not document_found and verification_code:
            docs = db.collection('documents').where('keywords', 'array-contains', verification_code).stream()
            for doc in docs:
                document_found = doc.to_dict()
                document_found['id'] = doc.id
                found_method = "by verification code in keywords"
                logger.info(f"Document found by verification code in keywords: {doc.id}")
                break
            
            # Try with keywords as a comma-separated string (some documents may store it this way)
            if not document_found:
                # Can't directly query for substring, so we need to process all documents with keywords
                # This is inefficient but necessary for backward compatibility
                keywords_docs = db.collection('documents').where('keywords', '!=', None).stream()
                for doc in keywords_docs:
                    doc_data = doc.to_dict()
                    keywords = doc_data.get('keywords', '')
                    if isinstance(keywords, str) and verification_code in keywords:
                        document_found = doc_data
                        document_found['id'] = doc.id
                        found_method = "by verification code in keywords string"
                        logger.info(f"Document found by verification code in keywords string: {doc.id}")
                        break
        
        if not document_found:
            logger.warning(f"Document not found in database by any method. Hash: {document_hash[:10]}...")
            return jsonify({
                "success": False,
                "verified": False,
                "hashValid": False,
                "message": "Document not found in our system."
            })
        
        # Log the document structure to help with debugging
        logger.info(f"Document structure: {str(document_found.keys())}")
        
        # Process signature_audit data for display
        signature_audit = document_found.get('signature_audit', [])
        processed_audit = []
        
        if signature_audit:
            # Process signature_audit data - handle both array and object formats
            if isinstance(signature_audit, list):
                # It's already an array
                processed_audit = signature_audit
                logger.info(f"Found signature_audit as array with {len(processed_audit)} entries")
            elif isinstance(signature_audit, dict):
                # Convert dictionary to array for consistency
                for timestamp, data in signature_audit.items():
                    if isinstance(data, dict):
                        # Add timestamp field if it doesn't exist
                        if 'timestamp' not in data:
                            data['timestamp'] = timestamp
                        processed_audit.append(data)
                    else:
                        # Simple value - create a dict with timestamp
                        processed_audit.append({'timestamp': timestamp, 'value': data})
                logger.info(f"Converted signature_audit from dict to array with {len(processed_audit)} entries")
            else:
                logger.warning(f"Unexpected signature_audit format: {type(signature_audit)}")
        
        # Check if this is the signed version or original version
        is_signed_version = document_found.get('hash_updated_after_signing', False)
        
        # Check for signatures
        signatures = []
        
        # Check if signatures are in the document itself
        if 'signatures' in document_found:
            doc_signatures = document_found.get('signatures', {})
            if isinstance(doc_signatures, dict):
                for sig_id, sig_data in doc_signatures.items():
                    signature_info = {
                        "id": sig_id,
                        "valid": True  # Default to true for simplicity
                    }
                    
                    if isinstance(sig_data, str):
                        # Handle the case where sig_data is just the base64 string
                        signature_info["signerName"] = "Document Signer"
                        signature_info["timestamp"] = document_found.get('signed_at', 'Unknown')
                    else:
                        # Normal case where sig_data is a dict with metadata
                        signature_info["signerName"] = sig_data.get('signer_name', 'Document Signer')
                        signature_info["signerEmail"] = sig_data.get('email')
                        signature_info["timestamp"] = sig_data.get('timestamp', document_found.get('signed_at', 'Unknown'))
                    
                    # Try to enhance with data from signature_audit
                    if processed_audit:
                        for audit_entry in processed_audit:
                            placeholders = audit_entry.get('placeholders_signed', [])
                            if str(sig_id) in map(str, placeholders):
                                signature_info["signerEmail"] = signature_info.get("signerEmail") or audit_entry.get('email')
                                signature_info["ip_address"] = audit_entry.get('ip_address')
                                signature_info["timestamp"] = signature_info.get("timestamp") or audit_entry.get('timestamp', 'Unknown')
                    
                    signatures.append(signature_info)
            
            logger.info(f"Found {len(signatures)} signatures in document data")
        
        # If no signatures found, check signature collection
        if not signatures and document_found.get('id'):
            signatures_query = db.collection('signatures').where('document_id', '==', document_found['id']).stream()
            for sig_doc in signatures_query:
                sig_data = sig_doc.to_dict()
                signatures.append({
                    "id": sig_doc.id,
                    "signerName": sig_data.get('signer_name', sig_data.get('user_email', 'Document Signer')),
                    "signerEmail": sig_data.get('user_email'),
                    "timestamp": sig_data.get('timestamp', document_found.get('signed_at', 'Unknown')),
                    "valid": True  # Default to true for simplicity
                })
            logger.info(f"Found {len(signatures)} signatures in signature collection")
        
        # If still no signatures found, extract from signature_audit
        if not signatures and processed_audit:
            for audit_entry in processed_audit:
                if isinstance(audit_entry, dict):  # Ensure it's a dict
                    # Create a signature entry from audit data
                    email = audit_entry.get('email')
                    if email:  # Only add if we have an email
                        placeholders = audit_entry.get('placeholders_signed', [])
                        sig_id = placeholders[0] if placeholders else str(len(signatures) + 1)
                        signatures.append({
                            "id": sig_id,
                            "signerName": email,
                            "signerEmail": email,
                            "timestamp": audit_entry.get('timestamp', 'Unknown'),
                            "ip_address": audit_entry.get('ip_address'),
                            "valid": True,
                            "placeholders": placeholders
                        })
            
            logger.info(f"Created {len(signatures)} signatures from signature_audit")
        
        # Add document info for the client - FIXED: Include all available fields
        document_info = {
            "document_id": document_found.get('id', document_found.get('document_id', 'Unknown')),
            "fileName": document_found.get('original_filename', 'Unknown'),
            "uploadDate": document_found.get('created_at', None),
            "lastSigned": document_found.get('signed_at', document_found.get('last_signed', None)),
            "status": document_found.get('status', 'verified' if signatures else 'unsigned'),
            # Add additional fields to help with audit trail
            "hash_updated_at": document_found.get('hash_updated_at'),
            "hash_updated_after_signing": document_found.get('hash_updated_after_signing', False),
            "updated_at": document_found.get('updated_at'),
            # Include the signature audit data if available
            "signature_audit": processed_audit
        }
        
        # Check hash match - consider special cases
        stored_hash = document_found.get('document_hash')
        hash_matches = False
        
        if stored_hash:
            hash_matches = document_hash == stored_hash
            logger.info(f"Hash comparison: {hash_matches} (calculated: {document_hash[:10]}..., stored: {stored_hash[:10]}...)")
        else:
            # No stored hash, but we found the document by ID or verification code
            # Consider it a partial match
            hash_matches = found_method != "by document hash"
            logger.info(f"No stored hash to compare, but document found {found_method}")
        
        # Document is verified if hash matches
        is_verified = hash_matches
        
        # Generate appropriate message
        if is_verified:
            if is_signed_version:
                message = "This is the signed version of the document. Verification successful."
            else:
                message = "This is the original unsigned version of the document. Verification successful."
        else:
            if document_found.get('hash_updated_after_signing') and not hash_matches:
                message = "This document has been modified after signing. The content does not match our records."
            else:
                message = "Document verification failed. This document may have been modified or is not from our system."
            
        logger.info(f"Verification result: {is_verified}, Message: {message}")
        
        # Check if verification code is valid
        verification_code_valid = False
        if verification_code:
            if document_found.get('verification_code') == verification_code:
                verification_code_valid = True
            elif document_found.get('keywords') and verification_code in document_found.get('keywords', ''):
                verification_code_valid = True
        
        return jsonify({
            "success": True,
            "verified": is_verified,
            "hashValid": hash_matches,
            "isSignedVersion": is_signed_version,
            "message": message,
            "signatures": signatures,
            "documentInfo": document_info,
            "verificationCodeValid": verification_code_valid
        })
        
    except Exception as e:
        logger.error(f"Error verifying document: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "success": False,
            "verified": False,
            "error": f"Verification error: {str(e)}"
        }), 500

@app.route('/api/upload-secure', methods=['POST'])
def api_upload_secure_document():
    """Handle document upload with placeholder positions"""
    try:
        logger.info("Document upload request received")
        
        if 'file' not in request.files:
            logger.warning("Upload request missing file part")
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.warning("Upload request has empty filename")
            return jsonify({"error": "No selected file"}), 400
        
        # Get password and placeholder positions from form
        password = request.form.get('password')
        if not password:
            logger.warning("Upload request missing password")
            return jsonify({"error": "Password is required"}), 400
        
        user_id = request.form.get('user_id', '')
        if not user_id:
            logger.warning("Upload request missing user ID")
            return jsonify({"error": "User ID is required"}), 400
        
        try:
            placeholder_positions = json.loads(request.form.get('placeholders', '[]'))
        except json.JSONDecodeError:
            logger.warning("Invalid placeholder format in upload request")
            return jsonify({"error": "Invalid placeholder format"}), 400
        
        # Read file data
        file_data = file.read()
        if not file_data:
            logger.warning("Uploaded file is empty")
            return jsonify({"error": "Uploaded file is empty"}), 400
        
        # Process the document
        document_manager = DocumentManager()
        document_id = document_manager.process_document_upload(file_data, file.filename, user_id, password, placeholder_positions)
        
        # Create links
        host = request.host_url.rstrip('/')
        signing_url = f"{host}/sign/{document_id}"
        view_url = f"{host}/document/{document_id}"
        
        logger.info(f"Document upload successful: {document_id}")
        return jsonify({
            "status": "success",
            "document_id": document_id,
            "signing_url": signing_url,
            "view_url": view_url
        })
    except Exception as e:
        logger.error(f"Document upload failed: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    
@app.route('/sign/<document_id>')
def get_document_for_signing(document_id):
    """Return the page for signing a document"""
    logger.info(f"Accessing sign page for document: {document_id}")
    try:
        return render_template('sign.html', document_id=document_id)
    except Exception as e:
        logger.error(f"Error rendering sign template: {str(e)}")
        return f"Error: {str(e)}", 500
    
@app.route('/sign/<document_id>/info', methods=['POST'])
def get_document_info(document_id):
    """Get document info for signing"""
    try:
        logger.info(f"Getting info for document: {document_id}")
        
        password = request.form.get('password')
        if not password:
            logger.warning("Password missing in document info request")
            return jsonify({"error": "Password is required"}), 400
        
        # Get user email from request
        user_email = request.form.get('userEmail', '').strip().lower()
        if user_email:
            logger.info(f"User email provided in request: {user_email}")
        else:
            logger.warning("No user email provided in document info request")
        
        try:
            # Get document info
            document_manager = DocumentManager()
            document_info = document_manager.get_document_info(document_id, password)
            
            # Log the placeholders to help debugging
            logger.info(f"Document info retrieved, placeholders: {document_info.get('placeholders', [])}")
            
            # Ensure placeholders property exists and is correctly named
            if 'placeholder_positions' in document_info and 'placeholders' not in document_info:
                document_info['placeholders'] = document_info.pop('placeholder_positions')
            
            # Add user's email to the response for client-side validation
            if user_email:
                document_info['currentUserEmail'] = user_email
            
            logger.info(f"Successfully retrieved document info: {document_id}")
            return jsonify(document_info)
        except ValueError as e:
            logger.error(f"Document info request validation error: {str(e)}")
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            logger.error(f"Document info retrieval error: {str(e)}")
            return jsonify({"error": f"Failed to get document info: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in get_document_info: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/sign/<document_id>/decrypt', methods=['POST'])
def decrypt_document_for_signing(document_id):
    """Decrypt document for viewing/signing"""
    try:
        logger.info(f"Decrypting document for signing: {document_id}")
        
        password = request.form.get('password')
        if not password:
            logger.warning("Password missing in decrypt request")
            return jsonify({"error": "Password is required"}), 400
        
        try:
            # Get document for signing (with embedded signatures)
            document_manager = DocumentManager()
            decrypted_data, original_filename, _ = document_manager.retrieve_document(document_id, password)
            
            # Create a temporary file to serve
            temp_file = io.BytesIO(decrypted_data)
            
            logger.info(f"Successfully decrypted document: {document_id}")
            # Return the decrypted document
            return send_file(
                temp_file,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"for_signing_{original_filename}"
            )
        except ValueError as e:
            logger.error(f"Document decrypt validation error: {str(e)}")
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            logger.error(f"Document decrypt error: {str(e)}")
            return jsonify({"error": f"Failed to decrypt document: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in decrypt_document_for_signing: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/sign/<document_id>/submit', methods=['POST'])
def submit_signature(document_id):
    """Apply signature to document and save it"""
    try:
        logger.info(f"Submitting signatures for document: {document_id}")
        
        password = request.form.get('password')
        if not password:
            logger.warning("Password missing in signature submission")
            return jsonify({"error": "Password is required"}), 400
        
        # Get signer email (for validation)
        signer_email = request.form.get('signerEmail', '').strip().lower()
        if not signer_email:
            logger.warning("Signer email missing in submission")
            return jsonify({"error": "Signer email is required"}), 400
            
        logger.info(f"Signer email: {signer_email}")
        
        # Get signature data
        try:
            signatures = json.loads(request.form.get('signatures', '{}'))
            if not signatures:
                logger.warning("No signatures provided in submission")
                return jsonify({"error": "No signatures provided"}), 400
        except json.JSONDecodeError:
            logger.warning("Invalid signature data format")
            return jsonify({"error": "Invalid signature data format"}), 400
        
        # Apply signature and save document
        try:
            document_manager = DocumentManager()
            
            # First get document info to validate email restrictions
            doc_ref = db.collection('documents').document(document_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                logger.error(f"Document ID {document_id} not found")
                return jsonify({"error": f"Document ID {document_id} not found"}), 404
                
            doc_data = doc.to_dict()
            placeholders = doc_data.get('placeholder_positions', [])
            
            # Validate that the signer is authorized for the placeholders they're signing
            for placeholder_id, signature_data in signatures.items():
                # Find the corresponding placeholder
                matching_placeholders = [p for p in placeholders if str(p['id']) == placeholder_id]
                if not matching_placeholders:
                    logger.warning(f"Placeholder ID {placeholder_id} not found in document")
                    return jsonify({"error": f"Placeholder ID {placeholder_id} not found in document"}), 400
                
                placeholder = matching_placeholders[0]
                required_email = placeholder.get('recipientEmail', '').strip().lower()
                
                if not required_email:
                    logger.warning(f"Attempted to sign placeholder {placeholder_id} with no assigned email")
                    return jsonify({
                        "error": f"You are not authorized to sign in placeholder {placeholder_id}. It has no recipient email assigned."
                    }), 403
                
                if required_email != signer_email:
                    logger.warning(f"Email authorization failed for placeholder {placeholder_id}: {required_email} vs {signer_email}")
                    return jsonify({
                        "error": f"You are not authorized to sign in placeholder {placeholder_id}. It is assigned to {required_email}."
                    }), 403
            
            # After validation, proceed with saving signatures
            result = document_manager.save_signed_document(document_id, password, signatures)
            
            # Add info about the signer to the audit trail
            doc_ref.update({
                "signature_audit": firestore.ArrayUnion([{
                    "email": signer_email,
                    "timestamp": datetime.now().isoformat(),
                    "ip_address": request.remote_addr,
                    "placeholders_signed": list(signatures.keys())
                }])
            })
            
            # NEW CODE: Update document hash immediately after signing
            try:
                # Retrieve the document with the new signatures
                updated_data, _, _ = document_manager.retrieve_document(document_id, password)
                
                # Calculate new hash of the signed document
                new_hash = hashlib.sha256(updated_data).hexdigest()
                
                # Update the hash in Firestore
                doc_ref.update({
                    'document_hash': new_hash,
                    'hash_updated_after_signing': True,
                    'hash_updated_at': datetime.now().isoformat()
                })
                
                logger.info(f"Updated document hash after signing: {new_hash}")
            except Exception as hash_error:
                logger.error(f"Error updating document hash after signing: {str(hash_error)}")
                # Continue with the response even if hash update fails
            
            logger.info(f"Successfully submitted signatures: {document_id}")
            return jsonify(result)
        except ValueError as e:
            logger.error(f"Signature submission validation error: {str(e)}")
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            logger.error(f"Signature submission error: {str(e)}")
            return jsonify({"error": f"Failed to sign document: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in submit_signature: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    
@app.route('/document/<document_id>')
def get_document_view(document_id):
    """Return the page for viewing a document"""
    logger.info(f"Accessing view page for document: {document_id}")
    try:
        return render_template('view.html', document_id=document_id)
    except Exception as e:
        logger.error(f"Error rendering view template: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/document/<document_id>/update-hash', methods=['POST'])
def update_document_hash(document_id):
    """Update the document hash after signing"""
    try:
        logger.info(f"Document hash update request: {document_id}")
        
        password = request.form.get('password')
        if not password:
            logger.warning("Password missing in document hash update request")
            return jsonify({"error": "Password is required"}), 400
        
        # Get document hash if provided
        document_hash = request.form.get('documentHash')
        verification_code = request.form.get('verificationCode', '')
        
        try:
            # Check if we need to calculate the hash or if it was provided
            if not document_hash:
                # If document hash not provided, calculate from the document
                document_manager = DocumentManager()
                pdf_data, original_filename, document_data = document_manager.retrieve_document(document_id, password)
                logger.info(f"Using retrieved document data for hash calculation")
                
                # Calculate hash for the document - use the whole document
                document_hash = hashlib.sha256(pdf_data).hexdigest()
            
            logger.info(f"Hash for signed document: {document_hash}")
            
            # Update document in Firestore
            update_data = {
                'document_hash': document_hash,
                'hash_updated_after_signing': True,  # Flag to identify signed documents
                'hash_updated_at': datetime.now().isoformat()
            }
            
            # Add verification code if provided
            if verification_code:
                update_data['verification_code'] = verification_code
                
                # Also add to keywords for easier search
                keywords = f"SecureSign,Verified,{document_id},{verification_code}"
                update_data['keywords'] = keywords
            
            doc_ref = db.collection('documents').document(document_id)
            doc_ref.update(update_data)
            
            logger.info(f"Successfully updated document hash: {document_id}")
            return jsonify({
                "success": True,
                "message": "Document hash updated successfully",
                "document_hash": document_hash
            })
        except ValueError as e:
            logger.error(f"Document hash update validation error: {str(e)}")
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            logger.error(f"Document hash update error: {str(e)}")
            return jsonify({"error": f"Failed to update document hash: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in update_document_hash: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/document/<document_id>/download', methods=['POST'])
def download_document(document_id):
    """Download a document (requires password)"""
    try:
        logger.info(f"Document download request: {document_id}")
        
        password = request.form.get('password')
        if not password:
            logger.warning("Password missing in document download request")
            return jsonify({"error": "Password is required"}), 400
        
        try:
            # Get document with embedded signatures
            document_manager = DocumentManager()
            decrypted_data, original_filename, _ = document_manager.retrieve_document(document_id, password)
            
            # Create a temporary file to serve
            temp_file = io.BytesIO(decrypted_data)
            
            logger.info(f"Successfully prepared document for download: {document_id}")
            # Return the decrypted document
            return send_file(
                temp_file,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"signed_{original_filename}"
            )
        except ValueError as e:
            logger.error(f"Document download validation error: {str(e)}")
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            logger.error(f"Document download error: {str(e)}")
            return jsonify({"error": f"Failed to retrieve document: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in download_document: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    
@app.route('/documents/<document_id>')
def redirect_to_document_view(document_id):
    """Redirect to the document view page (in case there's URL confusion)"""
    logger.info(f"Redirecting from /documents/{document_id} to /document/{document_id}")
    return redirect(f'/document/{document_id}')
    
@app.route('/verify')
def verify_document_page():
    """Document verification page"""
    return render_template('verify.html')

# Fixing file format, continuing from where it left off
@app.route('/api/test-connection', methods=['GET'])
def test_connection():
    """Test API connection"""
    return jsonify({
        "status": "success",
        "message": "SecureSign API is operational",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Get user profile information"""
    try:
        # Get user ID from auth token
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
            
        # Get user data from Firestore
        user_doc = db.collection('users').document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
            
        user_data = user_doc.to_dict()
        
        # Remove sensitive information
        if 'password' in user_data:
            del user_data['password']
            
        return jsonify({
            "success": True,
            "profile": user_data
        })
    except Exception as e:
        logger.error(f"Error getting user profile: {str(e)}")
        return jsonify({"error": f"Failed to get user profile: {str(e)}"}), 500

@app.route('/api/user/profile', methods=['PUT'])
def update_user_profile():
    """Update user profile information"""
    try:
        # Get user ID from auth token
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        
        # Get update data
        update_data = request.json
        if not update_data:
            return jsonify({"error": "No update data provided"}), 400
        
        # Allowable fields for update
        allowed_fields = ['displayName', 'company', 'jobTitle', 'phone']
        update_dict = {}
        
        for field in allowed_fields:
            if field in update_data:
                update_dict[field] = update_data[field]
        
        if not update_dict:
            return jsonify({"error": "No valid fields to update"}), 400
        
        # Update user document
        db.collection('users').document(user_id).update(update_dict)
        
        return jsonify({
            "success": True,
            "message": "Profile updated successfully"
        })
    except Exception as e:
        logger.error(f"Error updating user profile: {str(e)}")
        return jsonify({"error": f"Failed to update profile: {str(e)}"}), 500

@app.route('/api/document/share', methods=['POST'])
def share_document():
    """Share document with another user by email"""
    try:
        # Get user ID from auth token
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        
        # Get share data
        share_data = request.json
        if not share_data:
            return jsonify({"error": "No share data provided"}), 400
        
        document_id = share_data.get('documentId')
        recipient_email = share_data.get('email')
        
        if not document_id or not recipient_email:
            return jsonify({"error": "Document ID and recipient email are required"}), 400
        
        # Verify document exists and user has access
        doc_ref = db.collection('documents').document(document_id)
        doc = doc_ref.get()
        
        if not doc.exists:
            return jsonify({"error": "Document not found"}), 404
        
        doc_data = doc.to_dict()
        if doc_data.get('uploaded_by') != user_id:
            return jsonify({"error": "You do not have permission to share this document"}), 403
        
        # Create share record
        share_id = str(uuid.uuid4())
        share_data = {
            "share_id": share_id,
            "document_id": document_id,
            "shared_by": user_id,
            "recipient_email": recipient_email,
            "created_at": datetime.now().isoformat(),
            "status": "pending",
            "viewed": False
        }
        
        db.collection('document_shares').document(share_id).set(share_data)
        
        # In a real app, we would send an email notification here
        
        host = request.host_url.rstrip('/')
        signing_url = f"{host}/sign/{document_id}"
        
        logger.info(f"Document shared: {document_id} with {recipient_email}")
        return jsonify({
            "success": True,
            "share_id": share_id,
            "message": f"Document shared with {recipient_email}",
            "signing_url": signing_url
        })
    except Exception as e:
        logger.error(f"Error sharing document: {str(e)}")
        return jsonify({"error": f"Failed to share document: {str(e)}"}), 500

@app.route('/api/documents/statistics', methods=['GET'])
def get_document_statistics():
    """Get document statistics for a user"""
    try:
        # Get user ID from auth token
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        
        # Get all documents for the user
        docs = db.collection('documents').where('uploaded_by', '==', user_id).stream()
        
        total_documents = 0
        pending_signatures = 0
        signed_documents = 0
        
        for doc in docs:
            total_documents += 1
            doc_data = doc.to_dict()
            
            if doc_data.get('status') == 'signed':
                signed_documents += 1
            elif doc_data.get('status') in ['pending_signature', 'partially_signed']:
                pending_signatures += 1
        
        # Get documents shared with this user
        shared_docs = db.collection('document_shares').where('recipient_email', '==', 
            db.collection('users').document(user_id).get().to_dict().get('email', '')
        ).stream()
        
        shared_with_me = 0
        for _ in shared_docs:
            shared_with_me += 1
        
        return jsonify({
            "success": True,
            "statistics": {
                "total_documents": total_documents,
                "pending_signatures": pending_signatures,
                "signed_documents": signed_documents,
                "shared_with_me": shared_with_me
            }
        })
    except Exception as e:
        logger.error(f"Error getting document statistics: {str(e)}")
        return jsonify({"error": f"Failed to get statistics: {str(e)}"}), 500

@app.route('/api/document/templates', methods=['GET'])
def get_document_templates():
    """Get available document templates"""
    try:
        # This would typically fetch from a database, but for demo we'll return hardcoded data
        templates = [
            {
                "id": "template-nda",
                "name": "Non-Disclosure Agreement",
                "description": "Standard NDA template for business use",
                "category": "Legal",
                "preview_url": "/static/templates/nda-preview.jpg"
            },
            {
                "id": "template-employment",
                "name": "Employment Contract",
                "description": "Standard employment agreement template",
                "category": "HR",
                "preview_url": "/static/templates/employment-preview.jpg"
            },
            {
                "id": "template-rental",
                "name": "Rental Agreement",
                "description": "Property rental contract template",
                "category": "Real Estate",
                "preview_url": "/static/templates/rental-preview.jpg"
            }
        ]
        
        return jsonify({
            "success": True,
            "templates": templates
        })
    except Exception as e:
        logger.error(f"Error getting document templates: {str(e)}")
        return jsonify({"error": f"Failed to get templates: {str(e)}"}), 500

@app.route('/api/template/<template_id>', methods=['GET'])
def get_template(template_id):
    """Get a specific document template"""
    try:
        # In a real app, we would fetch this from the database
        # For demo, we'll check if it's one of our hardcoded templates
        template_map = {
            "template-nda": {
                "id": "template-nda",
                "name": "Non-Disclosure Agreement",
                "description": "Standard NDA template for business use",
                "category": "Legal",
                "file_path": "./static/templates/nda-template.pdf"
            },
            "template-employment": {
                "id": "template-employment",
                "name": "Employment Contract",
                "description": "Standard employment agreement template",
                "category": "HR",
                "file_path": "./static/templates/employment-template.pdf"
            },
            "template-rental": {
                "id": "template-rental",
                "name": "Rental Agreement",
                "description": "Property rental contract template",
                "category": "Real Estate",
                "file_path": "./static/templates/rental-template.pdf"
            }
        }
        
        if template_id not in template_map:
            return jsonify({"error": "Template not found"}), 404
        
        template = template_map[template_id]
        
        # For a real app, we would check if the file exists and return it
        # For demo, we'll just return the template info
        return jsonify({
            "success": True,
            "template": template
        })
    except Exception as e:
        logger.error(f"Error getting template: {str(e)}")
        return jsonify({"error": f"Failed to get template: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

# Implement a simple health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

# Run the Flask app
if __name__ == '__main__':
    logger.info("Starting SecureSign application")
    app.run(debug=True, host='0.0.0.0', port=5000)