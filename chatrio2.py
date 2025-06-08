# EnhancedChatrio.py - Modern P2P Chat with media sharing and Minecraft-style text effects
import socket
import threading
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox, filedialog
import time
import uuid
import queue
import pickle
import zlib
import base64
import os
import sys
import hashlib
import hmac
import secrets
import struct
import mimetypes
import random
from datetime import datetime, timedelta
from PIL import Image, ImageTk  # You'll need to install pillow: pip install pillow
from io import BytesIO

# Check for PyCryptodome
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad
except ImportError:
    messagebox.showerror("Missing Dependency", 
                        "PyCryptodome is required for this application.\n"
                        "Please install it using: pip install pycryptodomex")
    sys.exit(1)

# Check for themed widgets - these provide modern UI styles
try:
    # Sun Valley theme - gives a modern Windows 11 look
    import sv_ttk  # You'll need to install sun-valley-ttk: pip install sv-ttk
    HAS_SV_TTK = True
except ImportError:
    HAS_SV_TTK = False
    print("For an improved modern UI, install sv-ttk: pip install sv-ttk")

# Max file size for transfers (20MB)
MAX_FILE_SIZE = 20 * 1024 * 1024

# Minecraft obfuscation characters
OBFUSCATION_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"


class SecurityManager:
    """Handles all encryption/decryption operations"""
    
    def __init__(self, preshared_key=None):
        # Generate or use preshared key
        self.preshared_key = preshared_key or self._generate_preshared_key()
        
        # Generate RSA key pair for this client
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey().export_key()
        
        # Session keys for each peer
        self.session_keys = {}  # {peer_id: (key, expires_at)}
        
        # Message counters for replay protection
        self.message_counters = {}  # {peer_id: last_counter}
    
    def _generate_preshared_key(self):
        """Generate a random preshared key"""
        return base64.b64encode(get_random_bytes(32)).decode('utf-8')
    
    def get_public_key(self):
        """Get this client's public key"""
        return self.public_key
    
    def generate_session_key(self, peer_id, lifetime_minutes=30):
        """Generate a new session key for a peer"""
        session_key = get_random_bytes(32)  # 256 bits
        expires_at = datetime.now() + timedelta(minutes=lifetime_minutes)
        self.session_keys[peer_id] = (session_key, expires_at)
        return session_key
    
    def encrypt_session_key(self, session_key, peer_public_key):
        """Encrypt a session key with peer's public key"""
        try:
            # Import peer's public key
            peer_key = RSA.import_key(peer_public_key)
            
            # Create cipher
            cipher = PKCS1_OAEP.new(peer_key)
            
            # Encrypt session key
            encrypted_key = cipher.encrypt(session_key)
            
            return base64.b64encode(encrypted_key).decode('utf-8')
        except Exception as e:
            print(f"Error encrypting session key: {str(e)}")
            return None
    
    def decrypt_session_key(self, encrypted_key):
        """Decrypt a session key using our private key"""
        try:
            # Decode from base64
            encrypted_key = base64.b64decode(encrypted_key)
            
            # Create cipher
            cipher = PKCS1_OAEP.new(self.rsa_key)
            
            # Decrypt session key
            session_key = cipher.decrypt(encrypted_key)
            
            return session_key
        except Exception as e:
            print(f"Error decrypting session key: {str(e)}")
            return None
    
    def store_peer_session_key(self, peer_id, session_key, lifetime_minutes=30):
        """Store a received session key for a peer"""
        expires_at = datetime.now() + timedelta(minutes=lifetime_minutes)
        self.session_keys[peer_id] = (session_key, expires_at)
    
    def encrypt_message(self, peer_id, message):
        """Encrypt a message for a peer using AES-GCM"""
        try:
            # Check if we have a valid session key
            if peer_id not in self.session_keys:
                return None, "No session key"
            
            session_key, expires_at = self.session_keys[peer_id]
            
            # Check if session key is expired
            if datetime.now() > expires_at:
                return None, "Session key expired"
            
            # Convert message to JSON and then to bytes
            if isinstance(message, dict):
                message = json.dumps(message).encode('utf-8')
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            # Generate a new nonce (IV) for each message
            nonce = get_random_bytes(12)  # 96 bits for GCM
            
            # Get message counter for this peer
            counter = self.message_counters.get(peer_id, 0) + 1
            self.message_counters[peer_id] = counter
            
            # Current timestamp (as seconds since epoch)
            timestamp = int(time.time())
            
            # Expiration time (5 minutes from now)
            expires = timestamp + 300  # 5 minutes
            
            # Encode message metadata
            metadata = struct.pack('!QQ', counter, expires)
            
            # Create cipher
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            
            # Add metadata as associated data
            cipher.update(metadata)
            
            # Encrypt message
            ciphertext, tag = cipher.encrypt_and_digest(message)
            
            # Combine everything
            encrypted_data = {
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'counter': counter,
                'expires': expires
            }
            
            return encrypted_data, None
        
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return None, str(e)
    
    def decrypt_message(self, peer_id, encrypted_data):
        """Decrypt a message from a peer using AES-GCM"""
        try:
            # Check if we have a valid session key
            if peer_id not in self.session_keys:
                return None, "No session key"
            
            session_key, _ = self.session_keys[peer_id]
            
            # Extract components
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
            counter = encrypted_data['counter']
            expires = encrypted_data['expires']
            
            # Check if message is expired
            if int(time.time()) > expires:
                return None, "Message expired"
            
            # Check for replay attacks
            last_counter = self.message_counters.get(peer_id, 0)
            if counter <= last_counter:
                return None, "Replay attack detected"
            
            # Update counter
            self.message_counters[peer_id] = counter
            
            # Encode message metadata
            metadata = struct.pack('!QQ', counter, expires)
            
            # Create cipher
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            
            # Add metadata as associated data
            cipher.update(metadata)
            
            # Decrypt message
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Try to decode as JSON, fall back to string if not JSON
            try:
                return json.loads(plaintext.decode('utf-8')), None
            except:
                return plaintext.decode('utf-8'), None
        
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return None, str(e)
    
    def authenticate_peer(self, received_hmac, challenge):
        """Authenticate peer using the preshared key"""
        expected_hmac = hmac.new(
            self.preshared_key.encode('utf-8'),
            challenge.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(received_hmac, expected_hmac)
    
    def generate_auth_hmac(self, challenge):
        """Generate HMAC for authentication"""
        return hmac.new(
            self.preshared_key.encode('utf-8'),
            challenge.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def has_valid_session(self, peer_id):
        """Check if we have a valid session key for this peer"""
        if peer_id not in self.session_keys:
            return False
        
        _, expires_at = self.session_keys[peer_id]
        return datetime.now() < expires_at


class P2PNode:
    def __init__(self, host='0.0.0.0', port=0, preshared_key=None):
        """Initialize a P2P node that can act as both client and server"""
        self.host = host  # Listen on all interfaces
        self.port = port  # 0 means choose a random free port
        self.node_id = str(uuid.uuid4())
        self.username = None
        self.peers = {}  # {peer_id: (ip, port, username, public_key)}
        self.groups = {}  # {group_id: {name, members, messages}}
        
        # Security manager
        self.security = SecurityManager(preshared_key)
        
        # Connection management
        self.server_socket = None
        self.peer_connections = {}  # {peer_id: socket}
        self.message_queues = {}    # {peer_id: queue}
        
        # Message handling
        self.message_cache = {}     # {message_id: message_data}
        self.message_id_counter = 0
        
        # File transfer handling
        self.file_transfers = {}    # {transfer_id: {data, progress, ...}}
        
        # Handlers
        self.message_handlers = {}
        self.register_default_handlers()
        
        # Password protection system
        self.group_passwords = {}      # {group_id: hashed_password}
        self.password_attempts = {}    # {(peer_id, group_id): attempt_count}
        self.banned_peers = {}         # {(peer_id, group_id): ban_timestamp}
        self.max_password_attempts = 3
        self.ban_duration = 300        # 5 minutes in seconds
        
        # Startup
        self.start_server()
        
    def start_server(self):
        """Start the server socket to listen for incoming connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            
            # Get the actual port assigned if we used 0
            self.host, self.port = self.server_socket.getsockname()
            
            print(f"Node server started on {self.host}:{self.port}")
            
            # Start listener thread
            threading.Thread(target=self.listen_for_connections, daemon=True).start()
            
            # Start message dispatcher thread
            threading.Thread(target=self.message_dispatcher, daemon=True).start()
            
            # Start key renewal thread
            threading.Thread(target=self.key_renewal_thread, daemon=True).start()
            
            return True
        except Exception as e:
            print(f"Error starting server: {str(e)}")
            return False
    
    def listen_for_connections(self):
        """Listen for incoming connections"""
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                threading.Thread(target=self.handle_connection, args=(client_socket, address), daemon=True).start()
            except OSError:
                # Socket closed
                break
            except Exception as e:
                print(f"Error accepting connection: {str(e)}")
    
    def handle_connection(self, client_socket, address):
        """Handle an incoming connection"""
        try:
            # First message should be a handshake
            data = self.receive_data(client_socket)
            if data['type'] != 'handshake':
                client_socket.close()
                return
            
            # Extract basic info
            peer_id = data['node_id']
            username = data['username']
            port = data['port']  # The port they're listening on
            public_key = data['public_key']
            
            # Security handshake
            # 1. Generate a random challenge
            challenge = base64.b64encode(get_random_bytes(32)).decode('utf-8')
            
            # 2. Send challenge
            self.send_data(client_socket, {
                'type': 'auth_challenge',
                'challenge': challenge
            })
            
            # 3. Receive response with HMAC
            auth_response = self.receive_data(client_socket)
            if auth_response['type'] != 'auth_response':
                client_socket.close()
                return
            
            # 4. Verify HMAC
            if not self.security.authenticate_peer(auth_response['hmac'], challenge):
                self.send_data(client_socket, {
                    'type': 'handshake_response',
                    'success': False,
                    'message': 'Authentication failed'
                })
                client_socket.close()
                return
            
            # 5. Generate a session key
            session_key = self.security.generate_session_key(peer_id)
            
            # 6. Encrypt session key with peer's public key
            encrypted_key = self.security.encrypt_session_key(session_key, public_key)
            
            # Store peer info
            self.peers[peer_id] = (address[0], port, username, public_key)
            self.peer_connections[peer_id] = client_socket
            self.message_queues[peer_id] = queue.Queue()
            
            print(f"Connected with peer {username} ({peer_id}) at {address[0]}:{port}")
            
            # Send handshake response with encrypted session key
            self.send_data(client_socket, {
                'type': 'handshake_response',
                'node_id': self.node_id,
                'username': self.username,
                'port': self.port,
                'public_key': self.security.get_public_key().decode('utf-8'),
                'session_key': encrypted_key,
                'success': True
            })
            
            # Share known peers
            self.send_to_peer(peer_id, {
                'type': 'peer_list',
                'peers': self.peers
            })
            
            # Share group info for groups this peer should be part of
            self.share_groups_with_peer(peer_id)
            
            # Handle messages from this peer
            while True:
                data = self.receive_data(client_socket)
                threading.Thread(target=self.process_message, args=(peer_id, data), daemon=True).start()
        
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print(f"Peer disconnected")
        except Exception as e:
            print(f"Error handling peer connection: {str(e)}")
        finally:
            if 'peer_id' in locals() and peer_id in self.peer_connections:
                # Clean up connection
                self.disconnect_peer(peer_id)
    
    def connect_to_peer(self, ip, port):
        """Connect to a peer by IP and port"""
        try:
            # Create socket
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((ip, port))
            
            # Send handshake with our public key
            self.send_data(peer_socket, {
                'type': 'handshake',
                'node_id': self.node_id,
                'username': self.username,
                'port': self.port,
                'public_key': self.security.get_public_key().decode('utf-8')
            })
            
            # Wait for challenge
            challenge_data = self.receive_data(peer_socket)
            if challenge_data['type'] != 'auth_challenge':
                peer_socket.close()
                return False, "Invalid handshake response"
            
            # Calculate HMAC and respond
            challenge = challenge_data['challenge']
            hmac_result = self.security.generate_auth_hmac(challenge)
            
            self.send_data(peer_socket, {
                'type': 'auth_response',
                'hmac': hmac_result
            })
            
            # Wait for response with session key
            response = self.receive_data(peer_socket)
            if response['type'] != 'handshake_response' or not response.get('success'):
                error_msg = response.get('message', 'Handshake failed')
                peer_socket.close()
                return False, error_msg
            
            # Store peer info
            peer_id = response['node_id']
            username = response['username']
            listen_port = response['port']
            public_key = response['public_key']
            
            # Decrypt and store session key
            encrypted_key = response['session_key']
            session_key = self.security.decrypt_session_key(encrypted_key)
            
            if not session_key:
                peer_socket.close()
                return False, "Failed to decrypt session key"
            
            # Store session key
            self.security.store_peer_session_key(peer_id, session_key)
            
            # Store peer info
            self.peers[peer_id] = (ip, listen_port, username, public_key)
            self.peer_connections[peer_id] = peer_socket
            self.message_queues[peer_id] = queue.Queue()
            
            print(f"Connected to peer {username} ({peer_id}) at {ip}:{listen_port}")
            
            # Start listener thread for this connection
            threading.Thread(target=self.listen_to_peer, args=(peer_id, peer_socket), daemon=True).start()
            
            return True, peer_id
        except Exception as e:
            return False, str(e)
    
    def listen_to_peer(self, peer_id, peer_socket):
        """Listen for messages from a specific peer"""
        try:
            while True:
                data = self.receive_data(peer_socket)
                threading.Thread(target=self.process_message, args=(peer_id, data), daemon=True).start()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print(f"Peer {peer_id} disconnected")
        except Exception as e:
            print(f"Error listening to peer {peer_id}: {str(e)}")
        finally:
            self.disconnect_peer(peer_id)
    
    def disconnect_peer(self, peer_id):
        """Disconnect from a peer"""
        if peer_id in self.peer_connections:
            try:
                self.peer_connections[peer_id].close()
            except:
                pass
            
            del self.peer_connections[peer_id]
            
            if peer_id in self.message_queues:
                del self.message_queues[peer_id]
            
            # Clean up security info
            if peer_id in self.security.session_keys:
                del self.security.session_keys[peer_id]
            
            if peer_id in self.security.message_counters:
                del self.security.message_counters[peer_id]
            
            print(f"Disconnected from peer {peer_id}")
            
            # Notify about disconnection if we have handlers
            if hasattr(self, 'on_peer_disconnected'):
                self.on_peer_disconnected(peer_id)
    
    def disconnect_all(self):
        """Disconnect from all peers and stop the server"""
        # Disconnect all peers
        for peer_id in list(self.peer_connections.keys()):
            self.disconnect_peer(peer_id)
        
        # Stop the server
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
    
    def send_to_peer(self, peer_id, data):
        """Send data to a specific peer"""
        if peer_id in self.peer_connections:
            try:
                # Check if message needs encryption
                if data.get('type') not in ['handshake', 'handshake_response', 'auth_challenge', 'auth_response']:
                    # Encrypt message if we have a session key
                    if self.security.has_valid_session(peer_id):
                        encrypted_data, error = self.security.encrypt_message(peer_id, data)
                        if error:
                            print(f"Encryption error: {error}")
                            return False
                        
                        # Wrap encrypted data
                        data = {
                            'type': 'encrypted',
                            'data': encrypted_data
                        }
                
                self.send_data(self.peer_connections[peer_id], data)
                return True
            except Exception as e:
                print(f"Error sending to peer {peer_id}: {str(e)}")
                self.disconnect_peer(peer_id)
                return False
        return False
    
    def broadcast_to_peers(self, data, exclude_peer_id=None):
        """Broadcast data to all connected peers, optionally excluding one"""
        for peer_id in list(self.peer_connections.keys()):
            if peer_id != exclude_peer_id:
                self.send_to_peer(peer_id, data)
    
    def queue_message_to_peer(self, peer_id, data):
        """Queue a message to be sent to a peer"""
        if peer_id in self.message_queues:
            self.message_queues[peer_id].put(data)
    
    def message_dispatcher(self):
        """Thread that dispatches messages from queues to peers"""
        while True:
            # Process message queues for all peers
            for peer_id, msg_queue in list(self.message_queues.items()):
                if peer_id not in self.peer_connections:
                    continue
                
                # Get up to 10 messages at a time to send in batch
                messages = []
                for _ in range(10):
                    try:
                        messages.append(msg_queue.get_nowait())
                    except queue.Empty:
                        break
                
                if messages:
                    try:
                        # Send messages as batch
                        self.send_to_peer(peer_id, {
                            'type': 'message_batch',
                            'messages': messages
                        })
                    except Exception as e:
                        print(f"Error sending messages to peer {peer_id}: {str(e)}")
            
            # Sleep a short time to prevent CPU hogging
            time.sleep(0.01)
    
    def key_renewal_thread(self):
        """Thread that renews session keys periodically"""
        while True:
            for peer_id in list(self.peer_connections.keys()):
                try:
                    # Check if session key is about to expire
                    if peer_id in self.security.session_keys:
                        _, expires_at = self.security.session_keys[peer_id]
                        
                        # If key expires in less than 5 minutes, renew it
                        if datetime.now() + timedelta(minutes=5) > expires_at:
                            print(f"Renewing session key for peer {peer_id}")
                            
                            # Generate new session key
                            session_key = self.security.generate_session_key(peer_id)
                            
                            # Get peer's public key
                            _, _, _, public_key = self.peers[peer_id]
                            
                            # Encrypt session key
                            encrypted_key = self.security.encrypt_session_key(session_key, public_key)
                            
                            # Send key renewal message
                            self.send_to_peer(peer_id, {
                                'type': 'key_renewal',
                                'session_key': encrypted_key
                            })
                
                except Exception as e:
                    print(f"Error renewing key for peer {peer_id}: {str(e)}")
            
            # Sleep for 1 minute
            time.sleep(60)
    
    def process_message(self, peer_id, data):
        """Process a message from a peer"""
        try:
            # Check if message is encrypted
            if data.get('type') == 'encrypted':
                # Decrypt message
                decrypted, error = self.security.decrypt_message(peer_id, data['data'])
                if error:
                    print(f"Decryption error: {error}")
                    return
                
                # Replace encrypted data with decrypted
                data = decrypted
            
            message_type = data.get('type')
            
            # Handle message batches
            if message_type == 'message_batch':
                for message in data.get('messages', []):
                    self.process_message(peer_id, message)
                return
            
            # Handle key renewal
            if message_type == 'key_renewal':
                encrypted_key = data.get('session_key')
                session_key = self.security.decrypt_session_key(encrypted_key)
                
                if session_key:
                    # Store the new session key
                    self.security.store_peer_session_key(peer_id, session_key)
                    print(f"Received new session key from peer {peer_id}")
                return
            
            # Call the appropriate handler
            if message_type in self.message_handlers:
                self.message_handlers[message_type](peer_id, data)
            else:
                print(f"Unknown message type: {message_type}")
        except Exception as e:
            print(f"Error processing message: {str(e)}")
    
    def register_handler(self, message_type, handler_func):
        """Register a handler for a specific message type"""
        self.message_handlers[message_type] = handler_func
    
    
    def hash_password(self, password):
        """Hash a password for secure storage"""
        import hashlib
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def verify_password(self, password, hashed_password):
        """Verify a password against its hash"""
        return self.hash_password(password) == hashed_password
    
    def is_peer_banned(self, peer_id, group_id):
        """Check if a peer is banned from a group"""
        ban_key = (peer_id, group_id)
        if ban_key in self.banned_peers:
            ban_time = self.banned_peers[ban_key]
            if time.time() - ban_time < self.ban_duration:
                return True
            else:
                # Ban expired, remove it
                del self.banned_peers[ban_key]
                if ban_key in self.password_attempts:
                    del self.password_attempts[ban_key]
        return False
    
    def ban_peer_from_group(self, peer_id, group_id):
        """Ban a peer from a group for failed password attempts"""
        ban_key = (peer_id, group_id)
        self.banned_peers[ban_key] = time.time()
        print(f"Banned peer {peer_id} from group {group_id} for {self.ban_duration} seconds")
    
    def increment_password_attempt(self, peer_id, group_id):
        """Increment password attempt counter and check for ban"""
        attempt_key = (peer_id, group_id)
        self.password_attempts[attempt_key] = self.password_attempts.get(attempt_key, 0) + 1
        
        if self.password_attempts[attempt_key] >= self.max_password_attempts:
            self.ban_peer_from_group(peer_id, group_id)
            return True  # Peer is now banned
        return False  # Peer is not banned yet
    
    def reset_password_attempts(self, peer_id, group_id):
        """Reset password attempts for a peer on successful authentication"""
        attempt_key = (peer_id, group_id)
        if attempt_key in self.password_attempts:
            del self.password_attempts[attempt_key]
    
    def register_default_handlers(self):
        """Register default message handlers"""
        self.register_handler('peer_list', self.handle_peer_list)
        self.register_handler('create_group', self.handle_create_group)
        self.register_handler('join_group', self.handle_join_group)
        self.register_handler('leave_group', self.handle_leave_group)
        self.register_handler('chat_message', self.handle_chat_message)
        self.register_handler('group_info', self.handle_group_info)
        self.register_handler('request_group_info', self.handle_request_group_info)
        self.register_handler('group_password_challenge', self.handle_group_password_challenge)
        self.register_handler('group_password_response', self.handle_group_password_response)
        self.register_handler('group_access_denied', self.handle_group_access_denied)  # NEW
        self.register_handler('request_group_info', self.handle_request_group_info)
        self.register_handler('group_password_challenge', self.handle_group_password_challenge)
        self.register_handler('group_password_response', self.handle_group_password_response)
        self.register_handler('group_access_denied', self.handle_group_access_denied)  # NEW
        # File transfer handlers
        self.register_handler('file_chunk', self.handle_file_chunk)
        self.register_handler('file_request', self.handle_file_request)
        self.register_handler('file_complete', self.handle_file_complete)
    
    def handle_peer_list(self, peer_id, data):
        """Handle receiving a list of peers"""
        new_peers = data.get('peers', {})
        # Filter out our own ID and peers we already know
        new_peers = {pid: info for pid, info in new_peers.items() 
                    if pid != self.node_id and pid not in self.peers}
        
        # We don't automatically connect to these peers
        # The user would need to explicitly connect to them
        if hasattr(self, 'on_peer_list_received'):
            self.on_peer_list_received(new_peers)
    
    def handle_create_group(self, peer_id, data):
        """Handle group creation message with password support"""
        group_id = data.get('group_id')
        group_name = data.get('group_name')
        creator_id = data.get('creator_id')
        has_password = data.get('has_password', False)
        
        if group_id not in self.groups:
            # Create the group record
            self.groups[group_id] = {
                'name': group_name,
                'creator_id': creator_id,
                'members': {creator_id},  # Only creator initially
                'messages': [],
                'has_password': has_password
            }
            
            # If group has password, send challenge instead of auto-joining
            if has_password:
                challenge_id = str(uuid.uuid4())
                self.send_to_peer(peer_id, {
                    'type': 'group_password_challenge',
                    'group_id': group_id,
                    'group_name': group_name,
                    'challenge_id': challenge_id
                })
            else:
                # No password - auto-join and confirm
                self.groups[group_id]['members'].add(self.node_id)
                
                self.send_to_peer(peer_id, {
                    'type': 'join_group',
                    'group_id': group_id,
                    'member_id': self.node_id
                })
            
            # Notify UI about new group
            if hasattr(self, 'on_group_created'):
                self.on_group_created(group_id, group_name, creator_id)
    
    def handle_join_group(self, peer_id, data):
        """Handle someone joining a group - FIXED VERSION"""
        group_id = data.get('group_id')
        member_id = data.get('member_id')
        
        if group_id in self.groups:
            # Add the member
            self.groups[group_id]['members'].add(member_id)
            
            # If we're in a UI context, notify
            if hasattr(self, 'on_group_member_joined'):
                self.on_group_member_joined(group_id, member_id)
            
            # Share group history with the new member (only if we're not the one joining)
            if member_id != self.node_id:
                self.share_group_history(group_id, peer_id)
                
            # Broadcast the join to other members
            for other_peer_id in self.peer_connections:
                if (other_peer_id != peer_id and other_peer_id != member_id and
                    other_peer_id in self.groups[group_id]['members']):
                    self.send_to_peer(other_peer_id, data)
    
    def handle_leave_group(self, peer_id, data):
        """Handle someone leaving a group"""
        group_id = data.get('group_id')
        member_id = data.get('member_id')
        
        if group_id in self.groups and member_id in self.groups[group_id]['members']:
            self.groups[group_id]['members'].remove(member_id)
            
            # If we're in a UI context, notify
            if hasattr(self, 'on_group_member_left'):
                self.on_group_member_left(group_id, member_id)
    
    def handle_chat_message(self, peer_id, data):
        """Handle a chat message - FIXED VERSION"""
        group_id = data.get('group_id')
        message_id = data.get('message_id')
        sender_id = data.get('sender_id')
        content = data.get('content')
        timestamp = data.get('timestamp')
        obfuscated = data.get('obfuscated', False)
        
        # Check if we're a member of this group OR if we should auto-join
        if group_id not in self.groups:
            # Auto-join the group if we receive a message for it
            # This handles the case where someone sends a message before we properly joined
            self.groups[group_id] = {
                'name': f"Group-{group_id[:8]}",  # Temporary name
                'creator_id': sender_id,
                'members': {sender_id, self.node_id},
                'messages': []
            }
            
            # Request group info to get the proper name
            self.send_to_peer(peer_id, {
                'type': 'request_group_info',
                'group_id': group_id
            })
            
            # Notify UI about new group
            if hasattr(self, 'on_group_created'):
                self.on_group_created(group_id, self.groups[group_id]['name'], sender_id)
        
        # Only process if we're a member or if it's from a direct peer
        if (self.node_id in self.groups[group_id]['members'] or 
            sender_id in self.peer_connections or 
            peer_id in self.peer_connections):
            
            # Store message if we don't have it
            if message_id not in self.message_cache:
                message = {
                    'message_id': message_id,
                    'group_id': group_id,
                    'sender_id': sender_id,
                    'content': content,
                    'timestamp': timestamp,
                    'obfuscated': obfuscated
                }
                
                # Add to group's message list
                self.groups[group_id]['messages'].append(message)
                
                # Cache message
                self.message_cache[message_id] = message
                
                # If we're in a UI context, notify
                if hasattr(self, 'on_chat_message_received'):
                    self.on_chat_message_received(group_id, message)
            
            # Forward to other peers who might be in this group
            # but exclude the sender and the peer we got it from
            for other_peer_id in self.peer_connections:
                if other_peer_id != peer_id and other_peer_id != sender_id:
                    self.queue_message_to_peer(other_peer_id, data)
    
    def handle_group_info(self, peer_id, data):
        """Handle group info message"""
        group_id = data.get('group_id')
        group_name = data.get('group_name')
        members = set(data.get('members', []))
        messages = data.get('messages', [])
        
        if group_id not in self.groups:
            # New group for us
            self.groups[group_id] = {
                'name': group_name,
                'members': members,
                'messages': []
            }
        else:
            # Update existing group
            self.groups[group_id]['name'] = group_name
            self.groups[group_id]['members'].update(members)
        
        # Add messages we don't have yet
        for message in messages:
            msg_id = message.get('message_id')
            if msg_id not in self.message_cache:
                self.groups[group_id]['messages'].append(message)
                self.message_cache[msg_id] = message
        
        # Sort messages by timestamp
        self.groups[group_id]['messages'].sort(key=lambda m: m.get('timestamp', 0))
        
        # If we're in a UI context, notify
        if hasattr(self, 'on_group_info_received'):
            self.on_group_info_received(group_id, group_name, members)
    
    # File transfer handlers
    
    
    def handle_request_group_info(self, peer_id, data):
        """Handle a request for group information"""
        group_id = data.get('group_id')
        
        if group_id in self.groups:
            group = self.groups[group_id]
            
            # Send group info back
            self.send_to_peer(peer_id, {
                'type': 'group_info',
                'group_id': group_id,
                'group_name': group['name'],
                'members': list(group['members']),
                'messages': group['messages'][-50:]  # Last 50 messages
            })
    
    
    
    def handle_group_password_challenge(self, peer_id, data):
        """Handle a password challenge for group access"""
        group_id = data.get('group_id')
        challenge_id = data.get('challenge_id')
        
        # If we have a UI, prompt for password
        if hasattr(self, 'on_password_challenge_received'):
            self.on_password_challenge_received(peer_id, group_id, challenge_id)
    
    def handle_group_password_response(self, peer_id, data):
        """Handle a password response from a peer"""
        group_id = data.get('group_id')
        challenge_id = data.get('challenge_id')
        password = data.get('password')
        
        # Check if peer is banned
        if self.is_peer_banned(peer_id, group_id):
            remaining_time = self.ban_duration - (time.time() - self.banned_peers[(peer_id, group_id)])
            self.send_to_peer(peer_id, {
                'type': 'group_access_denied',
                'group_id': group_id,
                'reason': 'banned',
                'remaining_time': int(remaining_time)
            })
            return
        
        # Verify password
        if group_id in self.group_passwords:
            if self.verify_password(password, self.group_passwords[group_id]):
                # Password correct - reset attempts and allow access
                self.reset_password_attempts(peer_id, group_id)
                
                # Add peer to group
                if group_id in self.groups:
                    self.groups[group_id]['members'].add(peer_id)
                
                # Send group info
                self.send_to_peer(peer_id, {
                    'type': 'group_info',
                    'group_id': group_id,
                    'group_name': self.groups[group_id]['name'],
                    'members': list(self.groups[group_id]['members']),
                    'messages': self.groups[group_id]['messages'][-50:]
                })
                
                # Notify other members
                self.broadcast_to_peers({
                    'type': 'join_group',
                    'group_id': group_id,
                    'member_id': peer_id
                }, exclude_peer_id=peer_id)
                
            else:
                # Password incorrect
                is_banned = self.increment_password_attempt(peer_id, group_id)
                
                if is_banned:
                    self.send_to_peer(peer_id, {
                        'type': 'group_access_denied',
                        'group_id': group_id,
                        'reason': 'banned',
                        'remaining_time': self.ban_duration
                    })
                else:
                    attempts_left = self.max_password_attempts - self.password_attempts.get((peer_id, group_id), 0)
                    self.send_to_peer(peer_id, {
                        'type': 'group_access_denied',
                        'group_id': group_id,
                        'reason': 'wrong_password',
                        'attempts_left': attempts_left
                    })
    
    def handle_group_access_denied(self, peer_id, data):
        """Handle group access denial notification"""
        group_id = data.get('group_id')
        reason = data.get('reason')
        
        if hasattr(self, 'on_group_access_denied'):
            self.on_group_access_denied(group_id, reason, data)
    
    def handle_request_group_info(self, peer_id, data):
        """Handle a request for group information"""
        group_id = data.get('group_id')
        
        if group_id in self.groups:
            group = self.groups[group_id]
            
            # Send group info back
            self.send_to_peer(peer_id, {
                'type': 'group_info',
                'group_id': group_id,
                'group_name': group['name'],
                'members': list(group['members']),
                'messages': group['messages'][-50:]  # Last 50 messages
            })
    
    
    
    def handle_group_password_challenge(self, peer_id, data):
        """Handle a password challenge for group access"""
        group_id = data.get('group_id')
        challenge_id = data.get('challenge_id')
        
        # If we have a UI, prompt for password
        if hasattr(self, 'on_password_challenge_received'):
            self.on_password_challenge_received(peer_id, group_id, challenge_id)
    
    def handle_group_password_response(self, peer_id, data):
        """Handle a password response from a peer"""
        group_id = data.get('group_id')
        challenge_id = data.get('challenge_id')
        password = data.get('password')
        
        # Check if peer is banned
        if self.is_peer_banned(peer_id, group_id):
            remaining_time = self.ban_duration - (time.time() - self.banned_peers[(peer_id, group_id)])
            self.send_to_peer(peer_id, {
                'type': 'group_access_denied',
                'group_id': group_id,
                'reason': 'banned',
                'remaining_time': int(remaining_time)
            })
            return
        
        # Verify password
        if group_id in self.group_passwords:
            if self.verify_password(password, self.group_passwords[group_id]):
                # Password correct - reset attempts and allow access
                self.reset_password_attempts(peer_id, group_id)
                
                # Add peer to group
                if group_id in self.groups:
                    self.groups[group_id]['members'].add(peer_id)
                
                # Send group info
                self.send_to_peer(peer_id, {
                    'type': 'group_info',
                    'group_id': group_id,
                    'group_name': self.groups[group_id]['name'],
                    'members': list(self.groups[group_id]['members']),
                    'messages': self.groups[group_id]['messages'][-50:]
                })
                
                # Notify other members
                self.broadcast_to_peers({
                    'type': 'join_group',
                    'group_id': group_id,
                    'member_id': peer_id
                }, exclude_peer_id=peer_id)
                
            else:
                # Password incorrect
                is_banned = self.increment_password_attempt(peer_id, group_id)
                
                if is_banned:
                    self.send_to_peer(peer_id, {
                        'type': 'group_access_denied',
                        'group_id': group_id,
                        'reason': 'banned',
                        'remaining_time': self.ban_duration
                    })
                else:
                    attempts_left = self.max_password_attempts - self.password_attempts.get((peer_id, group_id), 0)
                    self.send_to_peer(peer_id, {
                        'type': 'group_access_denied',
                        'group_id': group_id,
                        'reason': 'wrong_password',
                        'attempts_left': attempts_left
                    })
    
    def handle_group_access_denied(self, peer_id, data):
        """Handle group access denial notification"""
        group_id = data.get('group_id')
        reason = data.get('reason')
        
        if hasattr(self, 'on_group_access_denied'):
            self.on_group_access_denied(group_id, reason, data)
    
    def handle_file_request(self, peer_id, data):
        """Handle a request for a file chunk - FIXED VERSION"""
        transfer_id = data.get('transfer_id')
        chunk_index = data.get('chunk_index')
        
        if transfer_id in self.file_transfers:
            transfer = self.file_transfers[transfer_id]
            
            # Check if we have this chunk
            if chunk_index < len(transfer['chunks']):
                chunk_data = transfer['chunks'][chunk_index]
                
                # Send the chunk with file info for first chunk
                response_data = {
                    'type': 'file_chunk',
                    'transfer_id': transfer_id,
                    'chunk_index': chunk_index,
                    'total_chunks': len(transfer['chunks']),
                    'chunk_data': chunk_data
                }
                
                # Include file info and group info for first chunk
                if chunk_index == 0:
                    response_data['file_info'] = transfer.get('file_info', {})
                    response_data['group_id'] = transfer.get('group_id')
                
                self.send_to_peer(peer_id, response_data)
    
    def handle_file_chunk(self, peer_id, data):
        """Handle receiving a file chunk - FIXED VERSION"""
        transfer_id = data.get('transfer_id')
        chunk_index = data.get('chunk_index')
        total_chunks = data.get('total_chunks')
        chunk_data = data.get('chunk_data')
        
        # Get or create file transfer record
        if transfer_id not in self.file_transfers:
            self.file_transfers[transfer_id] = {
                'chunks': [None] * total_chunks,
                'received_chunks': 0,
                'total_chunks': total_chunks,
                'file_info': data.get('file_info', {}),
                'group_id': data.get('group_id'),
                'sender_id': peer_id
            }
            
            # Notify UI about new transfer
            file_info = data.get('file_info', {})
            if hasattr(self, 'on_file_transfer_created'):
                self.on_file_transfer_created(
                    transfer_id, 
                    file_info.get('filename', 'Unknown'), 
                    file_info.get('file_type', ''), 
                    file_info.get('file_size', 0)
                )
        
        transfer = self.file_transfers[transfer_id]
        
        # Store the chunk if we don't have it
        if chunk_index < len(transfer['chunks']) and transfer['chunks'][chunk_index] is None:
            transfer['chunks'][chunk_index] = chunk_data
            transfer['received_chunks'] += 1
            
            # Update progress if we have a handler
            if hasattr(self, 'on_file_progress'):
                progress = transfer['received_chunks'] / transfer['total_chunks']
                self.on_file_progress(transfer_id, progress)
            
            # Request next chunk if we need it
            if transfer['received_chunks'] < transfer['total_chunks']:
                # Find next missing chunk
                for i, chunk in enumerate(transfer['chunks']):
                    if chunk is None:
                        # Request this chunk
                        self.send_to_peer(peer_id, {
                            'type': 'file_request',
                            'transfer_id': transfer_id,
                            'chunk_index': i
                        })
                        break
            else:
                # File is complete
                self.complete_file_transfer(transfer_id)
    
    def handle_file_complete(self, peer_id, data):
        """Handle notification that a peer has received a complete file"""
        transfer_id = data.get('transfer_id')
        
        # We can clean up our transfer record
        if transfer_id in self.file_transfers:
            # Notify any UI handlers
            if hasattr(self, 'on_file_delivered'):
                self.on_file_delivered(transfer_id, peer_id)
            
            # Keep the transfer data if we're the sender and there are more peers
            transfer = self.file_transfers[transfer_id]
            if transfer.get('sender_id') == self.node_id:
                delivered_to = transfer.get('delivered_to', set())
                delivered_to.add(peer_id)
                transfer['delivered_to'] = delivered_to
                
                # If delivered to all members, clean up
                group_id = transfer.get('group_id')
                if group_id in self.groups:
                    members = self.groups[group_id]['members']
                    if all(member in delivered_to for member in members if member != self.node_id):
                        del self.file_transfers[transfer_id]
            else:
                # We're a receiver, clean up
                del self.file_transfers[transfer_id]
    
    def complete_file_transfer(self, transfer_id):
        """Process a completed file transfer"""
        transfer = self.file_transfers[transfer_id]
        
        # Combine chunks
        combined_data = base64.b64decode(''.join(transfer['chunks']))
        
        # Add file info to the transfer
        file_info = transfer.get('file_info', {})
        file_info['data'] = combined_data
        transfer['file_info'] = file_info
        
        # Notify sender that we've received the complete file
        sender_id = transfer.get('sender_id')
        if sender_id in self.peer_connections:
            self.send_to_peer(sender_id, {
                'type': 'file_complete',
                'transfer_id': transfer_id
            })
        
        # Notify any UI handlers
        if hasattr(self, 'on_file_received'):
            self.on_file_received(transfer_id, file_info)
        
        # If this is part of a chat message, add it to the group
        group_id = transfer.get('group_id')
        message_id = file_info.get('message_id')
        
        if group_id and message_id and group_id in self.groups:
            if hasattr(self, 'on_chat_message_received'):
                # Create a message that references the file
                message = {
                    'message_id': message_id,
                    'group_id': group_id,
                    'sender_id': sender_id,
                    'content': file_info.get('filename', 'File'),
                    'timestamp': time.time(),
                    'file_transfer_id': transfer_id,
                    'file_type': file_info.get('file_type'),
                    'file_size': file_info.get('file_size')
                }
                
                # Add to group messages
                self.groups[group_id]['messages'].append(message)
                self.message_cache[message_id] = message
                
                # Notify UI
                self.on_chat_message_received(group_id, message)
    
    def create_group(self, group_name, password=None):
        """Create a new group with optional password protection"""
        group_id = str(uuid.uuid4())
        
        # Store group locally with just ourselves initially
        self.groups[group_id] = {
            'name': group_name,
            'creator_id': self.node_id,
            'members': {self.node_id},
            'messages': [],
            'has_password': password is not None
        }
        
        # Store password if provided
        if password:
            self.group_passwords[group_id] = self.hash_password(password)
        
        # Broadcast to all peers
        self.broadcast_to_peers({
            'type': 'create_group',
            'group_id': group_id,
            'group_name': group_name,
            'creator_id': self.node_id,
            'has_password': password is not None
        })
        
        print(f"Created group {group_name} ({group_id})" + (" with password protection" if password else ""))
        
        # Notify UI if we have a handler
        if hasattr(self, 'on_group_created'):
            self.on_group_created(group_id, group_name, self.node_id)
        
        return group_id
    
    def join_group(self, group_id):
        """Join an existing group"""
        if group_id not in self.groups:
            return False
        
        # Add ourselves to the group
        self.groups[group_id]['members'].add(self.node_id)
        
        # Broadcast to all peers
        self.broadcast_to_peers({
            'type': 'join_group',
            'group_id': group_id,
            'member_id': self.node_id
        })
        
        print(f"Joined group {self.groups[group_id]['name']} ({group_id})")
        
        return True
    
    def leave_group(self, group_id):
        """Leave a group"""
        if group_id not in self.groups:
            return False
        
        # Remove ourselves from the group
        if self.node_id in self.groups[group_id]['members']:
            self.groups[group_id]['members'].remove(self.node_id)
        
        # Broadcast to all peers
        self.broadcast_to_peers({
            'type': 'leave_group',
            'group_id': group_id,
            'member_id': self.node_id
        })
        
        print(f"Left group {self.groups[group_id]['name']} ({group_id})")
        
        return True
    
    def send_chat_message(self, group_id, content, obfuscated=False):
        """Send a chat message to a group - FIXED VERSION"""
        if group_id not in self.groups:
            return False
        
        # Generate message ID
        message_id = f"{self.node_id}-{self.message_id_counter}"
        self.message_id_counter += 1
        
        timestamp = time.time()
        
        # Create message
        message = {
            'type': 'chat_message',
            'message_id': message_id,
            'group_id': group_id,
            'sender_id': self.node_id,
            'content': content,
            'timestamp': timestamp,
            'obfuscated': obfuscated
        }
        
        # Store locally
        self.groups[group_id]['messages'].append(message)
        self.message_cache[message_id] = message
        
        # Send to ALL connected peers (they will filter based on group membership)
        # This ensures the message reaches everyone who should see it
        for peer_id in self.peer_connections:
            self.queue_message_to_peer(peer_id, message)
        
        # Notify UI if we have a handler
        if hasattr(self, 'on_chat_message_received'):
            self.on_chat_message_received(group_id, message)
        
        return True
    
    def send_file(self, group_id, file_path):
        """Send a file to a group - FIXED VERSION"""
        if group_id not in self.groups:
            return False, "Group not found"
        
        try:
            # Check if file exists and is within size limits
            if not os.path.exists(file_path):
                return False, "File not found"
            
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                return False, f"File too large (max {MAX_FILE_SIZE/1024/1024}MB)"
            
            # Generate transfer and message IDs
            transfer_id = str(uuid.uuid4())
            message_id = f"{self.node_id}-{self.message_id_counter}"
            self.message_id_counter += 1
            
            # Get file data and metadata
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(file_path)
            file_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            # Split into chunks (max 64KB per chunk for reliability)
            chunk_size = 64 * 1024
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            # Create file transfer record
            self.file_transfers[transfer_id] = {
                'chunks': chunks,
                'total_chunks': len(chunks),
                'received_chunks': len(chunks),  # We have all chunks as the sender
                'file_info': {
                    'filename': filename,
                    'file_type': file_type,
                    'file_size': file_size,
                    'message_id': message_id,
                    'data': file_data  # Store the actual file data for sender
                },
                'group_id': group_id,
                'sender_id': self.node_id,
                'delivered_to': set()
            }
            
            # Create a message referencing the file transfer
            message = {
                'type': 'chat_message',
                'message_id': message_id,
                'group_id': group_id,
                'sender_id': self.node_id,
                'content': filename,
                'timestamp': time.time(),
                'file_transfer_id': transfer_id,
                'file_type': file_type,
                'file_size': file_size
            }
            
            # Store locally
            self.groups[group_id]['messages'].append(message)
            self.message_cache[message_id] = message
            
            # Notify UI
            if hasattr(self, 'on_chat_message_received'):
                self.on_chat_message_received(group_id, message)
                
            # Notify of transfer creation
            if hasattr(self, 'on_file_transfer_created'):
                self.on_file_transfer_created(transfer_id, filename, file_type, file_size)
            
            # Send to ALL connected peers (they will auto-request chunks if interested)
            for peer_id in self.peer_connections:
                self.queue_message_to_peer(peer_id, message)
            
            return True, transfer_id
            
        except Exception as e:
            print(f"Error sending file: {str(e)}")
            return False, str(e)
    
    def request_file_chunk(self, transfer_id, chunk_index):
        """Request a specific chunk of a file"""
        if transfer_id in self.file_transfers:
            transfer = self.file_transfers[transfer_id]
            sender_id = transfer.get('sender_id')
            
            if sender_id in self.peer_connections:
                self.send_to_peer(sender_id, {
                    'type': 'file_request',
                    'transfer_id': transfer_id,
                    'chunk_index': chunk_index
                })
                return True
        
        return False
    
    def share_groups_with_peer(self, peer_id):
        """Share group information with a peer"""
        # Find groups this peer should be part of
        for group_id, group in self.groups.items():
            if peer_id in group['members'] or self.node_id in group['members']:
                # Share group info
                self.send_to_peer(peer_id, {
                    'type': 'group_info',
                    'group_id': group_id,
                    'group_name': group['name'],
                    'members': list(group['members']),
                    'messages': group['messages'][-50:]  # Last 50 messages
                })
    
    def share_group_history(self, group_id, peer_id):
        """Share group message history with a peer"""
        if group_id in self.groups and peer_id in self.peer_connections:
            # Send last 50 messages (or all if less)
            messages = self.groups[group_id]['messages'][-50:]
            
            self.send_to_peer(peer_id, {
                'type': 'group_info',
                'group_id': group_id,
                'group_name': self.groups[group_id]['name'],
                'members': list(self.groups[group_id]['members']),
                'messages': messages
            })
    
    def send_data(self, sock, data):
        """Send data over a socket with compression"""
        try:
            # Serialize data
            serialized = json.dumps(data).encode('utf-8')
            
            # Compress data
            compressed = zlib.compress(serialized)
            
            # Send data length first (4 bytes)
            length = len(compressed)
            sock.sendall(length.to_bytes(4, byteorder='big'))
            
            # Send the compressed data
            sock.sendall(compressed)
        except Exception as e:
            raise ConnectionError(f"Error sending data: {str(e)}")
    
    def receive_data(self, sock):
        """Receive data from a socket with compression"""
        try:
            # Receive data length first (4 bytes)
            length_bytes = sock.recv(4)
            if not length_bytes:
                raise ConnectionError("Connection closed")
            
            length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive the compressed data
            data = b''
            remaining = length
            while remaining > 0:
                chunk = sock.recv(min(remaining, 4096))
                if not chunk:
                    raise ConnectionError("Connection closed")
                data += chunk
                remaining -= len(chunk)
            
            # Decompress data
            decompressed = zlib.decompress(data)
            
            # Deserialize data
            return json.loads(decompressed.decode('utf-8'))
        except Exception as e:
            raise ConnectionError(f"Error receiving data: {str(e)}")


class ModernChatApp:
    """A modernized version of the ChatApp with Aero-inspired styling"""
    
    def __init__(self, master):
        self.master = master
        self.master.title("🔒 Enhanced P2P Chat - Secure & Private")
        self.master.geometry("1000x700")
        self.master.minsize(800, 600)
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Apply modern theme if available
        self.setup_theme()
        
        # Icon and resources
        self.load_resources()
        
        # Create P2P node
        self.node = None
        self.username = None
        self.preshared_key = None
        
        # UI elements
        self.current_group = None
        self.peer_frames = {}
        self.group_frames = {}
        
        # File transfers
        self.file_transfers = {}
        
        # Create UI
        self.create_ui()
    
    def setup_theme(self):
        """Set up the UI theme for modern appearance"""
        # Configure ttk style
        self.style = ttk.Style()
        
        # Try to use Sun Valley theme if available
        if HAS_SV_TTK:
            sv_ttk.set_theme("light")
            print("Using Sun Valley theme for modern UI")
        else:
            # Fall back to built-in themes that look more modern
            if sys.platform == "win32":
                try:
                    self.style.theme_use("vista")
                except:
                    try:
                        self.style.theme_use("winnative")
                    except:
                        pass
            elif sys.platform == "darwin":
                try:
                    self.style.theme_use("aqua")
                except:
                    pass
            else:
                try:
                    self.style.theme_use("clam")
                except:
                    pass
        
        # Custom styling
        self.style.configure("TButton", padding=6, relief="flat", background="#ddd")
        self.style.configure("TEntry", padding=6)
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0")
        self.style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("GroupButton.TButton", padding=8, font=("Segoe UI", 10))
        self.style.configure("SecurityLabel.TLabel", foreground="#008800", font=("Segoe UI", 9))
        
        # Configure the ttk notebook style for tabs
        self.style.configure("TNotebook", background="#f0f0f0", borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=[12, 4], font=("Segoe UI", 10))
        
        # Set application colors
        self.colors = {
            "bg": "#E6F3FF",
            "chat_bg": "#FFFFFF",
            "self_msg": "#DCF8C6",
            "other_msg": "#E7E7E7",
            "system_msg": "#F0F8FF",
            "security_color": "#4CAF50",
            "accent": "#0078D4",
            "obfuscated_bg": "#333333",
            "obfuscated_fg": "#999999",
            "skype_blue": "#00AFF0",
            "skype_blue_dark": "#0078D4",
            "header_bg": "#4A90E2",
            "sidebar_bg": "#F7F7F7"
        }
        
    def load_resources(self):
        """Load icons and other resources"""
        # Create icons - we'll use Unicode characters for now
        # In a real app, you'd load actual icon files
        self.icons = {
            "lock": "🔒",
            "unlock": "🔓",
            "user": "👤",
            "group": "👥",
            "send": "➤",
            "add": "➕",
            "remove": "❌",
            "info": "ℹ",
            "settings": "⚙",
            "file": "📄",
            "image": "🖼️",
            "video": "🎬",
            "pdf": "📑",
            "obfuscate": "✱"
        }
    
    def create_ui(self):
        """Create the user interface"""
        # Set window background
        self.master.configure(bg=self.colors["bg"])
        
        # Main container frame
        self.main_frame = ttk.Frame(self.master, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top area - connection details and status
        self.create_connection_area()
        
        # Content area - split view
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create a PanedWindow for resizable split view
        self.paned_window = ttk.PanedWindow(self.content_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left panel (sidebar) - peers and groups
        self.create_sidebar()
        
        # Right panel - chat area
        self.create_chat_area()
        
        # Status bar
        self.create_status_bar()
    
    def create_connection_area(self):
        """Create the connection setup area"""
        # Connection frame
        connection_frame = ttk.LabelFrame(self.main_frame, text="Connection Settings", padding=10)
        connection_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Set up grid layout
        connection_frame.columnconfigure(1, weight=1)
        connection_frame.columnconfigure(3, weight=1)
        connection_frame.columnconfigure(5, weight=1)
        
        # Connection controls
        self.port_var = tk.StringVar(value="0")  # 0 = random port
        self.username_var = tk.StringVar(value=f"User-{uuid.uuid4().hex[:6]}")
        self.key_var = tk.StringVar()
        
        # Row 1: Username and port
        ttk.Label(connection_frame, text="Username:").grid(row=0, column=0, padx=(0, 5), pady=5, sticky=tk.W)
        username_entry = ttk.Entry(connection_frame, textvariable=self.username_var, width=15)
        username_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(connection_frame, text="Listen Port:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        port_entry = ttk.Entry(connection_frame, textvariable=self.port_var, width=5)
        port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        # Row 1 (continued): Preshared key and start button
        ttk.Label(connection_frame, text="Preshared Key:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        key_entry = ttk.Entry(connection_frame, textvariable=self.key_var, width=20, show="•")
        key_entry.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W+tk.E)
        
        self.start_button = ttk.Button(connection_frame, text="Start Node", command=self.start_node)
        self.start_button.grid(row=0, column=6, padx=5, pady=5)
        
        # Row 2: Status display
        status_frame = ttk.Frame(connection_frame)
        status_frame.grid(row=1, column=0, columnspan=7, padx=5, pady=5, sticky=tk.W+tk.E)
        
        self.your_ip_var = tk.StringVar(value="Not started")
        self.your_port_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Offline")
        
        # Status indicators
        status_indicator_frame = ttk.Frame(status_frame)
        status_indicator_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Indicator with icon
        status_indicator = ttk.Label(status_indicator_frame, textvariable=self.status_var, foreground="red")
        status_indicator.pack(side=tk.LEFT, padx=(0, 10))
        
        # IP and port display
        ttk.Label(status_indicator_frame, text="IP:").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(status_indicator_frame, textvariable=self.your_ip_var).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(status_indicator_frame, text="Port:").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(status_indicator_frame, textvariable=self.your_port_var).pack(side=tk.LEFT)
        
        # Connect to peer controls
        peer_connect_frame = ttk.Frame(status_frame)
        peer_connect_frame.pack(side=tk.RIGHT)
        
        self.peer_ip_var = tk.StringVar()
        self.peer_port_var = tk.StringVar()
        
        ttk.Label(peer_connect_frame, text="Connect to:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Entry(peer_connect_frame, textvariable=self.peer_ip_var, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(peer_connect_frame, text=":").pack(side=tk.LEFT)
        ttk.Entry(peer_connect_frame, textvariable=self.peer_port_var, width=5).pack(side=tk.LEFT, padx=(0, 5))
        
        self.connect_button = ttk.Button(peer_connect_frame, text="Connect", command=self.connect_to_peer)
        self.connect_button.pack(side=tk.LEFT)
        self.connect_button.state(['disabled'])
    
    def create_sidebar(self):
        """Create the sidebar with tabs for peers and groups"""
        self.sidebar_frame = ttk.Frame(self.paned_window, padding=0, width=250)
        self.paned_window.add(self.sidebar_frame, weight=0)
        
        # Create notebook for tabs
        self.sidebar_tabs = ttk.Notebook(self.sidebar_frame)
        self.sidebar_tabs.pack(fill=tk.BOTH, expand=True)
        
        # Peers tab
        self.peers_tab = ttk.Frame(self.sidebar_tabs, padding=5)
        self.sidebar_tabs.add(self.peers_tab, text="Peers")
        
        # Peers list with scrollbar
        peers_frame = ttk.Frame(self.peers_tab)
        peers_frame.pack(fill=tk.BOTH, expand=True)
        
        peers_canvas = tk.Canvas(peers_frame, bg=self.colors["bg"], highlightthickness=0)
        peers_scrollbar = ttk.Scrollbar(peers_frame, orient="vertical", command=peers_canvas.yview)
        
        self.peers_list = ttk.Frame(peers_canvas, padding=5)
        
        peers_canvas.configure(yscrollcommand=peers_scrollbar.set)
        peers_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        peers_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        peers_canvas_window = peers_canvas.create_window((0, 0), window=self.peers_list, anchor="nw")
        
        # Configure canvas scrolling
        def configure_peers_canvas(event):
            peers_canvas.configure(scrollregion=peers_canvas.bbox("all"))
            # Update the width of the window
            peers_canvas.itemconfig(peers_canvas_window, width=event.width)
            
        self.peers_list.bind("<Configure>", configure_peers_canvas)
        peers_canvas.bind("<Configure>", lambda e: peers_canvas.itemconfig(peers_canvas_window, width=e.width))
        
        # Groups tab
        self.groups_tab = ttk.Frame(self.sidebar_tabs, padding=5)
        self.sidebar_tabs.add(self.groups_tab, text="Groups")
        
        # Create group button
        self.create_group_button = ttk.Button(
            self.groups_tab, 
            text="Create Group", 
            command=self.create_group,
            style="GroupButton.TButton"
        )
        self.create_group_button.pack(fill=tk.X, pady=(0, 5))
        self.create_group_button.state(['disabled'])
        
        # Groups list with scrollbar
        groups_frame = ttk.Frame(self.groups_tab)
        groups_frame.pack(fill=tk.BOTH, expand=True)
        
        groups_canvas = tk.Canvas(groups_frame, bg=self.colors["bg"], highlightthickness=0)
        groups_scrollbar = ttk.Scrollbar(groups_frame, orient="vertical", command=groups_canvas.yview)
        
        self.groups_list = ttk.Frame(groups_canvas, padding=5)
        
        groups_canvas.configure(yscrollcommand=groups_scrollbar.set)
        groups_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        groups_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        groups_canvas_window = groups_canvas.create_window((0, 0), window=self.groups_list, anchor="nw")
        
        # Configure canvas scrolling
        def configure_groups_canvas(event):
            groups_canvas.configure(scrollregion=groups_canvas.bbox("all"))
            # Update the width of the window
            groups_canvas.itemconfig(groups_canvas_window, width=event.width)
            
        self.groups_list.bind("<Configure>", configure_groups_canvas)
        groups_canvas.bind("<Configure>", lambda e: groups_canvas.itemconfig(groups_canvas_window, width=e.width))
        
        # Transfers tab
        self.transfers_tab = ttk.Frame(self.sidebar_tabs, padding=5)
        self.sidebar_tabs.add(self.transfers_tab, text="Transfers")
        
        # Transfers list with scrollbar
        transfers_frame = ttk.Frame(self.transfers_tab)
        transfers_frame.pack(fill=tk.BOTH, expand=True)
        
        transfers_canvas = tk.Canvas(transfers_frame, bg=self.colors["bg"], highlightthickness=0)
        transfers_scrollbar = ttk.Scrollbar(transfers_frame, orient="vertical", command=transfers_canvas.yview)
        
        self.transfers_list = ttk.Frame(transfers_canvas, padding=5)
        
        transfers_canvas.configure(yscrollcommand=transfers_scrollbar.set)
        transfers_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        transfers_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        transfers_canvas_window = transfers_canvas.create_window((0, 0), window=self.transfers_list, anchor="nw")
        
        # Configure canvas scrolling
        def configure_transfers_canvas(event):
            transfers_canvas.configure(scrollregion=transfers_canvas.bbox("all"))
            # Update the width of the window
            transfers_canvas.itemconfig(transfers_canvas_window, width=event.width)
            
        self.transfers_list.bind("<Configure>", configure_transfers_canvas)
        transfers_canvas.bind("<Configure>", lambda e: transfers_canvas.itemconfig(transfers_canvas_window, width=e.width))
    
    def create_chat_area(self):
        """Create the chat area"""
        self.chat_frame = ttk.Frame(self.paned_window, padding=10)
        self.paned_window.add(self.chat_frame, weight=1)
        
        # Group info header
        self.header_frame = ttk.Frame(self.chat_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.group_name_var = tk.StringVar(value="No active conversation")
        
        # Group header with name and controls
        group_header = ttk.Label(self.header_frame, textvariable=self.group_name_var, style="Header.TLabel")
        group_header.pack(side=tk.LEFT)
        
        # Group action buttons
        self.actions_frame = ttk.Frame(self.header_frame)
        self.actions_frame.pack(side=tk.RIGHT)
        
        self.info_button = ttk.Button(self.actions_frame, text="Info", command=self.show_group_info)
        self.info_button.pack(side=tk.LEFT, padx=2)
        self.info_button.state(['disabled'])
        
        self.leave_button = ttk.Button(self.actions_frame, text="Leave", command=self.leave_group)
        self.leave_button.pack(side=tk.LEFT, padx=2)
        self.leave_button.state(['disabled'])
        
        # Security indicator
        self.security_frame = ttk.Frame(self.chat_frame)
        self.security_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.security_var = tk.StringVar(value=f"{self.icons['lock']} Messages are end-to-end encrypted")
        security_label = ttk.Label(self.security_frame, textvariable=self.security_var, style="SecurityLabel.TLabel")
        security_label.pack(side=tk.LEFT)
        
        # Chat display area (with rounded corners effect)
        self.chat_display_frame = ttk.Frame(self.chat_frame, padding=0)
        self.chat_display_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create a custom frame for the chat area with a border
        chat_container = ttk.Frame(self.chat_display_frame, padding=1)
        chat_container.pack(fill=tk.BOTH, expand=True)
        
        # Chat text area with custom styling
        self.chat_text = scrolledtext.ScrolledText(
            chat_container, 
            wrap=tk.WORD, 
            state=tk.DISABLED,
            font=("Segoe UI", 10),
            padx=10,
            pady=10,
            bg=self.colors["chat_bg"],
            relief="flat"
        )
        self.chat_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for message styling
        self.chat_text.tag_configure("system", foreground="gray", justify="center", spacing1=5, spacing3=5)
        self.chat_text.tag_configure("self", background=self.colors["self_msg"], lmargin1=20, lmargin2=20, rmargin=20, spacing1=5, spacing3=5)
        self.chat_text.tag_configure("other", background=self.colors["other_msg"], lmargin1=20, lmargin2=20, rmargin=20, spacing1=5, spacing3=5)
        self.chat_text.tag_configure("timestamp", foreground="gray", font=("Segoe UI", 8))
        self.chat_text.tag_configure("username", font=("Segoe UI", 10, "bold"))
        self.chat_text.tag_configure("security", foreground=self.colors["security_color"], justify="center", spacing1=5, spacing3=5)
        self.chat_text.tag_configure("obfuscated", foreground=self.colors["obfuscated_fg"], background=self.colors["obfuscated_bg"])
        self.chat_text.tag_configure("media", background="#e8f4ff", spacing1=5, spacing3=5)
        
        # Message input area
        self.input_frame = ttk.Frame(self.chat_frame)
        self.input_frame.pack(fill=tk.X)
        
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(
            self.input_frame, 
            textvariable=self.message_var,
            font=("Segoe UI", 10)
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        self.message_entry.state(['disabled'])
        
        # Message controls frame
        controls_frame = ttk.Frame(self.input_frame)
        controls_frame.pack(side=tk.RIGHT)
        
        # Obfuscation toggle
        self.obfuscate_var = tk.BooleanVar(value=False)
        obfuscate_check = ttk.Checkbutton(
            controls_frame, 
            text=self.icons["obfuscate"],
            variable=self.obfuscate_var,
            style="Toggle.TCheckbutton"
        )
        obfuscate_check.pack(side=tk.LEFT, padx=2)
        
        # File attachment button
        self.attach_button = ttk.Button(
            controls_frame, 
            text=self.icons["file"],
            width=3,
            command=self.attach_file
        )
        self.attach_button.pack(side=tk.LEFT, padx=2)
        self.attach_button.state(['disabled'])
        
        # Send button
        self.send_button = ttk.Button(
            controls_frame, 
            text=self.icons["send"],
            width=3,
            command=self.send_message
        )
        self.send_button.pack(side=tk.LEFT, padx=2)
        self.send_button.state(['disabled'])
    
    def create_status_bar(self):
        """Create the status bar at the bottom of the window"""
        status_bar = ttk.Frame(self.master, relief=tk.SUNKEN, padding=(2, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Connection status
        self.connection_status_var = tk.StringVar(value="Not connected")
        connection_status = ttk.Label(status_bar, textvariable=self.connection_status_var, padding=(5, 0))
        connection_status.pack(side=tk.LEFT)
        
        # Version info
        version_label = ttk.Label(status_bar, text="Enhanced P2P Chat v1.0", padding=(5, 0))
        version_label.pack(side=tk.RIGHT)
    
    def start_node(self):
        """Start the P2P node"""
        if self.node is not None:
            self.stop_node()
        
        username = self.username_var.get()
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
        
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
        
        preshared_key = self.key_var.get()
        if not preshared_key:
            # Generate random key
            random_key = base64.b64encode(get_random_bytes(32)).decode('utf-8')
            self.key_var.set(random_key)
            preshared_key = random_key
            messagebox.showinfo("Security", 
                             f"A random preshared key has been generated. Share this key with peers:\n\n{preshared_key}\n\n"
                             f"You must use the same preshared key to connect to each other.")
        
        # Create node
        self.node = P2PNode(port=port, preshared_key=preshared_key)
        self.node.username = username
        
        # Store for later
        self.preshared_key = preshared_key
        
        # Register callbacks
        self.node.on_peer_disconnected = self.on_peer_disconnected
        self.node.on_peer_list_received = self.on_peer_list_received
        self.node.on_group_created = self.on_group_created
        self.node.on_group_member_joined = self.on_group_member_joined
        self.node.on_group_member_left = self.on_group_member_left
        self.node.on_chat_message_received = self.on_chat_message_received
        self.node.on_group_info_received = self.on_group_info_received
        self.node.on_file_transfer_created = self.on_file_transfer_created
        self.node.on_file_progress = self.on_file_progress
        self.node.on_file_received = self.on_file_received
        self.node.on_file_delivered = self.on_file_delivered
        self.node.on_password_challenge_received = self.on_password_challenge_received
        self.node.on_group_access_denied = self.on_group_access_denied
        
        # Update UI
        self.username = username
        self.your_ip_var.set(self.get_local_ip())
        self.your_port_var.set(str(self.node.port))
        self.status_var.set("Online")
        self.connection_status_var.set(f"Online as {username}")
        
        # Update UI elements
        self.start_button.config(text="Stop Node")
        self.connect_button.state(['!disabled'])
        self.create_group_button.state(['!disabled'])
        
        messagebox.showinfo("Node Started", 
                           f"Your secure node is running on port {self.node.port}.\n"
                           f"Share your IP ({self.get_local_ip()}) and port with others to connect.")
    
    def stop_node(self):
        """Stop the P2P node"""
        if self.node is not None:
            self.node.disconnect_all()
            self.node = None
        
        # Update UI
        self.your_ip_var.set("Not started")
        self.your_port_var.set("")
        self.status_var.set("Offline")
        self.connection_status_var.set("Not connected")
        
        self.start_button.config(text="Start Node")
        self.connect_button.state(['disabled'])
        self.create_group_button.state(['disabled'])
        self.leave_button.state(['disabled'])
        self.info_button.state(['disabled'])
        self.message_entry.state(['disabled'])
        self.send_button.state(['disabled'])
        self.attach_button.state(['disabled'])
        
        # Clear UI
        self.clear_peers_list()
        self.clear_groups_list()
        self.clear_transfers_list()
        self.clear_chat()
        self.current_group = None
        self.group_name_var.set("No active conversation")
        self.file_transfers = {}
    
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            # Create a temporary socket to determine the IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's DNS server
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    def connect_to_peer(self):
        """Connect to a peer using IP and port"""
        if self.node is None:
            messagebox.showerror("Error", "You must start your node first")
            return
        
        peer_ip = self.peer_ip_var.get()
        if not peer_ip:
            messagebox.showerror("Error", "Peer IP is required")
            return
        
        try:
            peer_port = int(self.peer_port_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid peer port")
            return
        
        # Connect in a separate thread to avoid UI freezing
        threading.Thread(target=self._connect_to_peer_thread, 
                         args=(peer_ip, peer_port), daemon=True).start()
    
    def _connect_to_peer_thread(self, peer_ip, peer_port):
        """Thread for connecting to a peer"""
        try:
            success, result = self.node.connect_to_peer(peer_ip, peer_port)
            
            if success:
                peer_id = result
                self.master.after(0, lambda: self.add_peer_to_list(peer_id))
                self.master.after(0, lambda: messagebox.showinfo("Connected", 
                                                             f"Securely connected to peer at {peer_ip}:{peer_port}"))
            else:
                self.master.after(0, lambda: messagebox.showerror("Connection Failed", 
                                                             f"Failed to connect: {result}"))
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Connection Error", str(e)))
    
    
    def create_group_with_password_dialog(self):
        """Show dialog to create group with optional password"""
        dialog = tk.Toplevel(self.master)
        dialog.title("Create New Group")
        dialog.geometry("500x450")
        dialog.resizable(False, False)
        dialog.transient(self.master)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.master.winfo_rootx() + 50, self.master.winfo_rooty() + 50))
        
        # Content frame
        content_frame = tk.Frame(dialog, bg="#E6F3FF", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(content_frame, text="Create New Group", 
                              font=("Segoe UI", 14, "bold"), bg="#F0F0F0")
        title_label.pack(pady=(0, 20))
        
        # Group name
        tk.Label(content_frame, text="Group Name:", font=("Segoe UI", 10), bg="#F0F0F0").pack(anchor=tk.W)
        name_var = tk.StringVar()
        name_entry = tk.Entry(content_frame, textvariable=name_var, font=("Segoe UI", 10), width=30)
        name_entry.pack(fill=tk.X, pady=(5, 15))
        name_entry.focus()
        
        # Password protection checkbox
        password_enabled = tk.BooleanVar()
        password_check = tk.Checkbutton(content_frame, text="🔒 Password protect this group", 
                                       variable=password_enabled, font=("Segoe UI", 10),
                                       bg="#F0F0F0", command=lambda: self.toggle_password_fields(password_enabled.get(), password_frame))
        password_check.pack(anchor=tk.W, pady=(0, 10))
        
        # Password fields (initially hidden)
        password_frame = tk.Frame(content_frame, bg="#F0F0F0")
        password_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(password_frame, text="Password:", font=("Segoe UI", 10), bg="#F0F0F0").pack(anchor=tk.W)
        password_var = tk.StringVar()
        password_entry = tk.Entry(password_frame, textvariable=password_var, show="•", 
                                 font=("Segoe UI", 10), width=30)
        password_entry.pack(fill=tk.X, pady=(5, 10))
        
        tk.Label(password_frame, text="Confirm Password:", font=("Segoe UI", 10), bg="#F0F0F0").pack(anchor=tk.W)
        confirm_var = tk.StringVar()
        confirm_entry = tk.Entry(password_frame, textvariable=confirm_var, show="•", 
                                font=("Segoe UI", 10), width=30)
        confirm_entry.pack(fill=tk.X, pady=(5, 0))
        
        # Initially hide password fields
        password_frame.pack_forget()
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg="#F0F0F0")
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def create_group():
            group_name = name_var.get().strip()
            if not group_name:
                tk.messagebox.showerror("Error", "Group name is required")
                return
            
            password = None
            if password_enabled.get():
                password = password_var.get()
                confirm = confirm_var.get()
                
                if not password:
                    tk.messagebox.showerror("Error", "Password is required when protection is enabled")
                    return
                
                if password.strip() != confirm.strip():
                    tk.messagebox.showerror("Error", "Passwords do not match", parent=dialog)
                    return
                
                if len(password) < 4:
                    tk.messagebox.showerror("Error", "Password must be at least 4 characters")
                    return
            
            # Create the group
            group_id = self.node.create_group(group_name, password)
            self.select_group(group_id)
            dialog.destroy()
        
        tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                 bg="#6C757D", fg="white", font=("Segoe UI", 10), padx=15).pack(side=tk.RIGHT, padx=(5, 0))
        
        tk.Button(button_frame, text="Create Group", command=create_group,
                 bg="#007BFF", fg="white", font=("Segoe UI", 10, "bold"), padx=15).pack(side=tk.RIGHT)
        
        # Bind Enter key
        def on_enter(event):
            create_group()
        
        dialog.bind('<Return>', on_enter)
        
        return dialog
    
    def toggle_password_fields(self, enabled, password_frame):
        """Show or hide password fields based on checkbox"""
        if enabled:
            password_frame.pack(fill=tk.X, pady=(10, 15))
            # Focus on the first password field
            for widget in password_frame.winfo_children():
                if isinstance(widget, tk.Entry):
                    widget.focus()
                    break
        else:
            password_frame.pack_forget()
    
    def show_password_challenge_dialog(self, peer_id, group_id, group_name, challenge_id):
        """Show password input dialog for joining a protected group"""
        dialog = tk.Toplevel(self.master)
        dialog.title("Group Password Required")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.transient(self.master)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.master.winfo_rootx() + 100, self.master.winfo_rooty() + 100))
        
        # Content frame
        content_frame = tk.Frame(dialog, bg="#E6F3FF", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Icon and title
        tk.Label(content_frame, text="🔒", font=("Segoe UI", 24), bg="#F0F0F0").pack(pady=(0, 10))
        tk.Label(content_frame, text=f"Password Required", 
                font=("Segoe UI", 12, "bold"), bg="#F0F0F0").pack()
        tk.Label(content_frame, text=f"Group: {group_name}", 
                font=("Segoe UI", 10), bg="#F0F0F0", fg="#666").pack(pady=(5, 15))
        
        # Password input
        tk.Label(content_frame, text="Enter password:", font=("Segoe UI", 10), bg="#F0F0F0").pack(anchor=tk.W)
        password_var = tk.StringVar()
        password_entry = tk.Entry(content_frame, textvariable=password_var, show="•", 
                                 font=("Segoe UI", 10), width=25)
        password_entry.pack(fill=tk.X, pady=(5, 15))
        password_entry.focus()
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg="#F0F0F0")
        button_frame.pack(fill=tk.X)
        
        def submit_password():
            password = password_var.get()
            if not password:
                tk.messagebox.showerror("Error", "Password is required")
                return
            
            # Send password response
            self.node.send_to_peer(peer_id, {
                'type': 'group_password_response',
                'group_id': group_id,
                'challenge_id': challenge_id,
                'password': password
            })
            
            dialog.destroy()
        
        tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                 bg="#6C757D", fg="white", font=("Segoe UI", 9), padx=12).pack(side=tk.RIGHT, padx=(5, 0))
        
        tk.Button(button_frame, text="Join Group", command=submit_password,
                 bg="#28A745", fg="white", font=("Segoe UI", 9, "bold"), padx=12).pack(side=tk.RIGHT)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: submit_password())
    
    def create_group(self):
        """Create a new group with password dialog"""
        if self.node is None:
            return
        
        self.create_group_with_password_dialog()
    
    def leave_group(self):
        """Leave the current group"""
        if self.node is None or self.current_group is None:
            return
        
        result = messagebox.askyesno(
            "Leave Group",
            f"Are you sure you want to leave this group?",
            parent=self.master
        )
        
        if result:
            group_name = self.node.groups[self.current_group]['name']
            
            if self.node.leave_group(self.current_group):
                # Remove from UI
                self.remove_group_from_list(self.current_group)
                
                # Clear current group
                self.current_group = None
                self.group_name_var.set("No active conversation")
                self.clear_chat()
                
                # Disable group actions
                self.leave_button.state(['disabled'])
                self.info_button.state(['disabled'])
                self.message_entry.state(['disabled'])
                self.send_button.state(['disabled'])
                self.attach_button.state(['disabled'])
                
                messagebox.showinfo("Group Left", f"You have left the group '{group_name}'")
    
    def show_group_info(self):
        """Show information about the current group"""
        if self.node is None or self.current_group is None:
            return
        
        group = self.node.groups[self.current_group]
        
        # Get member usernames
        member_usernames = []
        for member_id in group['members']:
            if member_id == self.node.node_id:
                member_usernames.append(f"{self.node.username} (You)")
            else:
                username = "Unknown"
                for peer_id, (_, _, peer_username, _) in self.node.peers.items():
                    if peer_id == member_id:
                        username = peer_username
                        break
                member_usernames.append(username)
        
        # Create a custom dialog for group info
        info_dialog = tk.Toplevel(self.master)
        info_dialog.title(f"Group: {group['name']}")
        info_dialog.geometry("400x350")
        info_dialog.resizable(False, False)
        info_dialog.transient(self.master)
        info_dialog.grab_set()
        
        # Apply theme to dialog
        if HAS_SV_TTK:
            sv_ttk.set_theme("light", info_dialog)
        
        # Content frame
        content_frame = ttk.Frame(info_dialog, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Group name
        ttk.Label(content_frame, text=group['name'], style="Header.TLabel").pack(pady=(0, 15))
        
        # Members count
        ttk.Label(content_frame, text=f"Members ({len(group['members'])})").pack(anchor=tk.W, pady=(0, 5))
        
        # Members list with scrollbar
        members_frame = ttk.Frame(content_frame, padding=5, relief="solid")
        members_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        members_list = tk.Listbox(members_frame, relief="flat", font=("Segoe UI", 10))
        members_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        members_scrollbar = ttk.Scrollbar(members_frame, orient="vertical", command=members_list.yview)
        members_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        members_list.config(yscrollcommand=members_scrollbar.set)
        
        # Add members to list
        for username in sorted(member_usernames):
            members_list.insert(tk.END, username)
        
        # Security info
        security_frame = ttk.LabelFrame(content_frame, text="Security", padding=10)
        security_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(security_frame, text=f"{self.icons['lock']} All messages are encrypted with AES-256-GCM",
                foreground=self.colors["security_color"]).pack(anchor=tk.W)
        ttk.Label(security_frame, text=f"{self.icons['lock']} Session keys are renewed automatically",
                foreground=self.colors["security_color"]).pack(anchor=tk.W)
        ttk.Label(security_frame, text=f"{self.icons['lock']} Files are securely transferred with end-to-end encryption",
                foreground=self.colors["security_color"]).pack(anchor=tk.W)
        
        # Group stats
        stats_frame = ttk.Frame(content_frame)
        stats_frame.pack(fill=tk.X)
        
        ttk.Label(stats_frame, text=f"Total messages: {len(group['messages'])}").pack(side=tk.LEFT)
        
        # Close button
        ttk.Button(content_frame, text="Close", command=info_dialog.destroy).pack(pady=(15, 0))
    
    def send_message(self):
        """Send a message to the current group"""
        if self.node is None or self.current_group is None:
            return
        
        content = self.message_var.get().strip()
        if not content:
            return
        
        # Get obfuscation status
        obfuscated = self.obfuscate_var.get()
        
        # Clear input field
        self.message_var.set("")
        
        # Send message
        self.node.send_chat_message(self.current_group, content, obfuscated)
    
    def attach_file(self):
        """Attach and send a file"""
        if self.node is None or self.current_group is None:
            return
        
        # Ask for file
        file_types = [
            ("Images", "*.jpg *.jpeg *.png *.gif *.bmp"),
            ("Documents", "*.pdf *.doc *.docx *.txt"),
            ("Videos", "*.mp4 *.avi *.mov *.mkv"),
            ("All files", "*.*")
        ]
        
        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=file_types,
            parent=self.master
        )
        
        if not file_path:
            return
        
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            messagebox.showerror(
                "File too large", 
                f"File is too large. Maximum size is {MAX_FILE_SIZE/1024/1024:.1f}MB."
            )
            return
        
        # Start file transfer in a separate thread
        threading.Thread(
            target=self._send_file_thread,
            args=(file_path,),
            daemon=True
        ).start()
    
    def _send_file_thread(self, file_path):
        """Thread function for sending files"""
        try:
            success, result = self.node.send_file(self.current_group, file_path)
            
            if not success:
                self.master.after(0, lambda: messagebox.showerror("File Error", result))
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("File Error", str(e)))
    
    def display_file(self, file_info, in_chat=True, tag="self"):
        """Display a file in the chat or in a separate window"""
        file_type = file_info.get('file_type', '')
        data = file_info.get('data')
        
        if not data:
            return
        
        if in_chat:
            self.chat_text.config(state=tk.NORMAL)
            
            # File container frame in a text window
            text_idx = self.chat_text.index(tk.INSERT)
            
            file_frame = ttk.Frame(self.chat_text)
            
            if file_type.startswith('image/'):
                # Display image
                try:
                    img = Image.open(BytesIO(data))
                    
                    # Resize if too large
                    max_width = 300
                    max_height = 200
                    
                    if img.width > max_width or img.height > max_height:
                        img.thumbnail((max_width, max_height))
                    
                    # Convert to Tkinter PhotoImage
                    photo = ImageTk.PhotoImage(img)
                    
                    # Image label
                    img_label = ttk.Label(file_frame, image=photo)
                    img_label.image = photo  # Keep a reference to prevent garbage collection
                    img_label.pack(pady=5)
                    
                    # Image info
                    filename = file_info.get('filename', 'Image')
                    ttk.Label(file_frame, text=filename).pack()
                except Exception as e:
                    ttk.Label(file_frame, text=f"Error loading image: {str(e)}").pack()
            
            elif file_type.startswith('video/'):
                # Video thumbnail (would need external library for actual playback)
                video_icon = ttk.Label(file_frame, text=self.icons['video'], font=("Segoe UI", 36))
                video_icon.pack(pady=5)
                
                # Video info
                filename = file_info.get('filename', 'Video')
                size_mb = file_info.get('file_size', 0) / (1024 * 1024)
                ttk.Label(file_frame, text=f"{filename} ({size_mb:.1f} MB)").pack()
                
                # Play button
                play_btn = ttk.Button(
                    file_frame, 
                    text="Open Video",
                    command=lambda: self.save_and_open_file(file_info)
                )
                play_btn.pack(pady=5)
            
            elif file_type == 'application/pdf':
                # PDF icon
                pdf_icon = ttk.Label(file_frame, text=self.icons['pdf'], font=("Segoe UI", 36))
                pdf_icon.pack(pady=5)
                
                # PDF info
                filename = file_info.get('filename', 'Document')
                size_mb = file_info.get('file_size', 0) / (1024 * 1024)
                ttk.Label(file_frame, text=f"{filename} ({size_mb:.1f} MB)").pack()
                
                # Open button
                open_btn = ttk.Button(
                    file_frame, 
                    text="Open PDF",
                    command=lambda: self.save_and_open_file(file_info)
                )
                open_btn.pack(pady=5)
            
            else:
                # Generic file icon
                file_icon = ttk.Label(file_frame, text=self.icons['file'], font=("Segoe UI", 36))
                file_icon.pack(pady=5)
                
                # File info
                filename = file_info.get('filename', 'File')
                size_mb = file_info.get('file_size', 0) / (1024 * 1024)
                ttk.Label(file_frame, text=f"{filename} ({size_mb:.1f} MB)").pack()
                
                # Save button
                save_btn = ttk.Button(
                    file_frame, 
                    text="Save File",
                    command=lambda: self.save_file(file_info)
                )
                save_btn.pack(pady=5)
            
            # Insert the frame into the text widget
            self.chat_text.window_create(tk.END, window=file_frame)
            self.chat_text.insert(tk.END, "\n")
            
            # Add tags
            self.chat_text.tag_add(tag, text_idx, tk.END)
            self.chat_text.tag_add("media", text_idx, tk.END)
            
            # Scroll to see the new content
            self.chat_text.see(tk.END)
            self.chat_text.config(state=tk.DISABLED)
        
        else:
            # Open in separate window for full-size viewing
            if file_type.startswith('image/'):
                self.open_image_viewer(file_info)
            else:
                self.save_and_open_file(file_info)
    
    def open_image_viewer(self, file_info):
        """Open an image in a separate viewer window"""
        try:
            img = Image.open(BytesIO(file_info.get('data')))
            
            # Create a new window
            viewer = tk.Toplevel(self.master)
            viewer.title(file_info.get('filename', 'Image Viewer'))
            
            # Size the window based on the image but cap at screen size
            screen_width = self.master.winfo_screenwidth() - 100
            screen_height = self.master.winfo_screenheight() - 100
            
            width = min(img.width, screen_width)
            height = min(img.height, screen_height)
            
            viewer.geometry(f"{width}x{height}")
            
            # If image needs resizing
            if img.width > width or img.height > height:
                img = img.copy()  # Create a copy to resize
                img.thumbnail((width, height))
            
            # Convert and display
            photo = ImageTk.PhotoImage(img)
            label = ttk.Label(viewer, image=photo)
            label.image = photo  # Keep a reference
            label.pack(fill=tk.BOTH, expand=True)
            
            # Save button
            save_btn = ttk.Button(
                viewer, 
                text="Save Image As...",
                command=lambda: self.save_file(file_info)
            )
            save_btn.pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Image View Error", str(e))
    
    def save_file(self, file_info):
        """Save a file to disk"""
        if not file_info.get('data'):
            messagebox.showerror("File Error", "No file data available")
            return
        
        filename = file_info.get('filename', 'file')
        
        # Ask for save location
        save_path = filedialog.asksaveasfilename(
            title="Save File As",
            initialfile=filename,
            parent=self.master
        )
        
        if not save_path:
            return
        
        try:
            with open(save_path, 'wb') as f:
                f.write(file_info.get('data'))
            messagebox.showinfo("File Saved", f"File saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))
    
    def save_and_open_file(self, file_info):
        """Save a file and attempt to open it with the default application"""
        if not file_info.get('data'):
            messagebox.showerror("File Error", "No file data available")
            return
        
        filename = file_info.get('filename', 'file')
        
        # Ask for save location
        save_path = filedialog.asksaveasfilename(
            title="Save File As",
            initialfile=filename,
            parent=self.master
        )
        
        if not save_path:
            return
        
        try:
            with open(save_path, 'wb') as f:
                f.write(file_info.get('data'))
            
            # Attempt to open the file with the default application
            if sys.platform == 'win32':
                os.startfile(save_path)
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open "{save_path}"')
            else:  # Linux
                os.system(f'xdg-open "{save_path}"')
                
        except Exception as e:
            messagebox.showerror("Error", f"File saved but could not be opened: {str(e)}")
    
    def clear_peers_list(self):
        """Clear the peers list in UI"""
        for widget in self.peers_list.winfo_children():
            widget.destroy()
        self.peer_frames = {}
    
    def clear_groups_list(self):
        """Clear the groups list in UI"""
        for widget in self.groups_list.winfo_children():
            widget.destroy()
        self.group_frames = {}
    
    def clear_transfers_list(self):
        """Clear the transfers list in UI"""
        for widget in self.transfers_list.winfo_children():
            widget.destroy()
    
    def add_peer_to_list(self, peer_id):
        """Add a peer to the UI list"""
        if peer_id not in self.node.peers:
            return
        
        ip, port, username, _ = self.node.peers[peer_id]
        
        # Create modern peer card with light glass effect
        peer_frame = ttk.Frame(self.peers_list, padding=5)
        peer_frame.pack(fill=tk.X, pady=2, ipady=5)
        
        # Use a modern card layout
        inner_frame = ttk.Frame(peer_frame, padding=8)
        inner_frame.pack(fill=tk.X)
        
        # Add peer info with lock icon to show encryption
        icon_label = ttk.Label(inner_frame, text=self.icons["lock"], font=("Segoe UI", 12))
        icon_label.pack(side=tk.LEFT, padx=(0, 5))
        
        info_frame = ttk.Frame(inner_frame)
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(info_frame, text=username, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"{ip}:{port}", font=("Segoe UI", 8)).pack(anchor=tk.W)
        
        # Add disconnect button with modern styling
        disconnect_btn = ttk.Button(
            inner_frame, 
            text=self.icons["remove"],
            width=3,
            command=lambda p=peer_id: self.disconnect_peer(p)
        )
        disconnect_btn.pack(side=tk.RIGHT, padx=5)
        
        # Store reference
        self.peer_frames[peer_id] = peer_frame
    
    def remove_peer_from_list(self, peer_id):
        """Remove a peer from the UI list"""
        if peer_id in self.peer_frames:
            self.peer_frames[peer_id].destroy()
            del self.peer_frames[peer_id]
    
    def disconnect_peer(self, peer_id):
        """Disconnect from a peer"""
        if self.node is None:
            return
        
        self.node.disconnect_peer(peer_id)
        self.remove_peer_from_list(peer_id)
    
    def add_group_to_list(self, group_id):
        """Add a group to the UI list"""
        if group_id not in self.node.groups:
            return
        
        group_name = self.node.groups[group_id]['name']
        
        # Create modern group card
        group_frame = ttk.Frame(self.groups_list, padding=5)
        group_frame.pack(fill=tk.X, pady=2)
        
        # Use a modern card layout with hover effect
        inner_frame = ttk.Frame(group_frame, padding=8)
        inner_frame.pack(fill=tk.X)
        
        # Add group info
        icon_label = ttk.Label(inner_frame, text=self.icons["group"], font=("Segoe UI", 12))
        icon_label.pack(side=tk.LEFT, padx=(0, 5))
        
        # Make the whole frame clickable
        group_label = ttk.Label(
            inner_frame, 
            text=f"{group_name}",
            font=("Segoe UI", 10, "bold")
        )
        group_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Bind click event to the whole card
        for widget in [group_frame, inner_frame, icon_label, group_label]:
            widget.bind("<Button-1>", lambda e, gid=group_id: self.select_group(gid))
            widget.bind("<Enter>", lambda e, frame=inner_frame: self._on_group_enter(frame))
            widget.bind("<Leave>", lambda e, frame=inner_frame: self._on_group_leave(frame))
        
        # Store button reference
        self.group_frames[group_id] = group_frame
    
    def _on_group_enter(self, frame):
        """Highlight the group when mouse enters"""
        frame.configure(style="Hover.TFrame")
    
    def _on_group_leave(self, frame):
        """Remove highlight when mouse leaves"""
        frame.configure(style="TFrame")
    
    def remove_group_from_list(self, group_id):
        """Remove a group from the UI list"""
        if group_id in self.group_frames:
            self.group_frames[group_id].destroy()
            del self.group_frames[group_id]
    
    def add_transfer_to_list(self, transfer_id, filename, file_type, file_size):
        """Add a file transfer to the UI list"""
        # Create a frame for this transfer
        transfer_frame = ttk.Frame(self.transfers_list, padding=5)
        transfer_frame.pack(fill=tk.X, pady=2)
        
        # Get the appropriate icon based on file type
        icon = self.icons["file"]
        if file_type and file_type.startswith("image/"):
            icon = self.icons["image"]
        elif file_type and file_type.startswith("video/"):
            icon = self.icons["video"]
        elif file_type == "application/pdf":
            icon = self.icons["pdf"]
        
        # Add icon and filename
        icon_label = ttk.Label(transfer_frame, text=icon, font=("Segoe UI", 12))
        icon_label.pack(side=tk.LEFT, padx=(0, 5))
        
        info_frame = ttk.Frame(transfer_frame)
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Filename and size
        ttk.Label(info_frame, text=filename, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        
        size_mb = file_size / (1024 * 1024) if file_size else 0
        ttk.Label(info_frame, text=f"{size_mb:.1f} MB", font=("Segoe UI", 8)).pack(anchor=tk.W)
        
        # Progress bar
        self.transfer_progress_vars = getattr(self, 'transfer_progress_vars', {})
        self.transfer_progress_vars[transfer_id] = tk.DoubleVar(value=0.0)
        
        progress = ttk.Progressbar(
            transfer_frame, 
            variable=self.transfer_progress_vars[transfer_id],
            length=200
        )
        progress.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        # Store reference
        self.file_transfers[transfer_id] = {
            'frame': transfer_frame,
            'progress': progress,
            'filename': filename,
            'file_type': file_type,
            'file_size': file_size
        }
    
    def update_transfer_progress(self, transfer_id, progress):
        """Update the progress of a file transfer"""
        if transfer_id in self.transfer_progress_vars:
            self.transfer_progress_vars[transfer_id].set(progress * 100)
    
    def select_group(self, group_id):
        """Select a group and show its messages"""
        if self.node is None or group_id not in self.node.groups:
            return
        
        self.current_group = group_id
        group_name = self.node.groups[group_id]['name']
        self.group_name_var.set(f"{self.icons['lock']} {group_name}")
        
        # Highlight the selected group
        for gid, frame in self.group_frames.items():
            if gid == group_id:
                frame.configure(style="Selected.TFrame")
            else:
                frame.configure(style="TFrame")
        
        # Enable group actions
        self.leave_button.state(['!disabled'])
        self.info_button.state(['!disabled'])
        self.message_entry.state(['!disabled'])
        self.send_button.state(['!disabled'])
        self.attach_button.state(['!disabled'])
        
        # Show messages
        self.clear_chat()
        
        # Add a system message showing we selected this group
        self.add_system_message(f"Entered group: {group_name}")
        self.add_system_message(f"All messages are protected with AES-256-GCM encryption")
        
        # Show all messages in this group
        for message in self.node.groups[group_id]['messages']:
            sender_id = message.get('sender_id')
            content = message.get('content')
            timestamp = message.get('timestamp')
            obfuscated = message.get('obfuscated', False)
            
            # Handle file messages
            if 'file_transfer_id' in message:
                file_transfer_id = message.get('file_transfer_id')
                file_type = message.get('file_type')
                file_size = message.get('file_size')
                
                # Get sender info
                sender_name = "Unknown"
                if sender_id == self.node.node_id:
                    sender_name = f"{self.node.username} (You)"
                    tag = "self"
                else:
                    for peer_id, (_, _, peer_username, _) in self.node.peers.items():
                        if peer_id == sender_id:
                            sender_name = peer_username
                            break
                    tag = "other"
                
                # If we're the sender or if we already have the complete file, display it
                if sender_id == self.node.node_id or (
                    file_transfer_id in self.node.file_transfers and 
                    'file_info' in self.node.file_transfers[file_transfer_id] and
                    'data' in self.node.file_transfers[file_transfer_id]['file_info']
                ):
                    file_info = self.node.file_transfers[file_transfer_id]['file_info'] if file_transfer_id in self.node.file_transfers else {
                        'filename': content,
                        'file_type': file_type,
                        'file_size': file_size
                    }
                    
                    # Add the timestamp and sender first
                    self.chat_text.config(state=tk.NORMAL)
                    if timestamp:
                        time_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
                        self.chat_text.insert(tk.END, f"\n[{time_str}] ", "timestamp")
                    
                    # Add sender name based on who sent it
                    self.chat_text.insert(tk.END, f"{sender_name} shared a file:\n", tag)
                    self.chat_text.config(state=tk.DISABLED)
                    
                    # Add file visualization
                    self.display_file(file_info, tag=tag)
                
                else:
                    # We need to request the file
                    self.add_chat_message(sender_id, sender_name, f"[File: {content}]", timestamp)
                    
                    # If transfer doesn't exist or isn't complete, request it
                    if (file_transfer_id not in self.node.file_transfers or 
                        self.node.file_transfers[file_transfer_id].get('received_chunks', 0) < 
                        self.node.file_transfers[file_transfer_id].get('total_chunks', 1)):
                        
                        # Create a transfer record if it doesn't exist
                        if file_transfer_id not in self.node.file_transfers:
                            self.node.file_transfers[file_transfer_id] = {
                                'file_info': {
                                    'filename': content,
                                    'file_type': file_type,
                                    'file_size': file_size,
                                    'message_id': message.get('message_id')
                                },
                                'sender_id': sender_id,
                                'group_id': group_id,
                                'chunks': [],
                                'received_chunks': 0,
                                'total_chunks': 0
                            }
                            
                            # Add to transfers list
                            self.master.after(0, lambda: self.add_transfer_to_list(
                                file_transfer_id, content, file_type, file_size
                            ))
                            
                            # Request the first chunk
                            self.node.request_file_chunk(file_transfer_id, 0)
                
            else:
                # Regular text message
                sender_name = "Unknown"
                if sender_id == self.node.node_id:
                    sender_name = f"{self.node.username} (You)"
                else:
                    for peer_id, (_, _, peer_username, _) in self.node.peers.items():
                        if peer_id == sender_id:
                            sender_name = peer_username
                            break
                
                self.add_chat_message(sender_id, sender_name, content, timestamp, obfuscated)
        
        # Focus message entry
        self.message_entry.focus_set()
    
    def clear_chat(self):
        """Clear the chat area"""
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)
        self.chat_text.config(state=tk.DISABLED)
    
    def add_chat_message(self, sender_id, sender_name, content, timestamp=None, obfuscated=False):
        """Add a message to the chat area with modern styling"""
        self.chat_text.config(state=tk.NORMAL)
        
        # Determine message tag based on sender
        tag = "self" if sender_id == self.node.node_id else "other"
        
        # Create a message bubble
        self.chat_text.insert(tk.END, "\n")  # Space before the message
        
        # Start of message block
        msg_start = self.chat_text.index(tk.END)
        
        # Add timestamp if available
        if timestamp:
            time_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
            self.chat_text.insert(tk.END, f"[{time_str}] ", "timestamp")
        
        # Add sender name based on who sent it
        self.chat_text.insert(tk.END, f"{sender_name}\n", "username")
        
        # If obfuscated, make the message appear as Minecraft obfuscated text until hovered
        if obfuscated:
            # Insert obfuscated content with randomly chosen symbols
            obfuscated_text = ''.join(random.choice(OBFUSCATION_CHARS) for _ in range(len(content)))
            
            # Add the obfuscated content with special tags
            obfuscated_index = self.chat_text.index(tk.END)
            self.chat_text.insert(tk.END, f"{obfuscated_text}\n", "obfuscated")
            
            # Store the real text in a hidden attribute for use on hover
            # This needs to be within a try/except because older tkinter versions
            # might not support custom attributes
            try:
                self.chat_text.tag_configure("obfuscated", background=self.colors["obfuscated_bg"])
                self.chat_text._real_text = content  # Store real text for hover reference
                
                # Bind hover events to reveal/hide the real text
                real_content_tag = f"real_content_{sender_id}_{timestamp or time.time()}"
                self.chat_text.tag_add(real_content_tag, obfuscated_index, f"{obfuscated_index} + {len(obfuscated_text)} chars")
                self.chat_text.tag_bind(real_content_tag, "<Enter>", 
                                     lambda e, idx=obfuscated_index, txt=content: self._reveal_obfuscated_text(idx, txt))
                self.chat_text.tag_bind(real_content_tag, "<Leave>", 
                                     lambda e, idx=obfuscated_index, txt=obfuscated_text: self._hide_obfuscated_text(idx, txt))
            except:
                # Fallback if the hover effect isn't supported
                self.chat_text.insert(tk.END, f"(Hover to reveal)\n", "timestamp")
        else:
            # Add normal content
            self.chat_text.insert(tk.END, f"{content}\n", tag)
        
        # Scroll to bottom
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)
    
    def _reveal_obfuscated_text(self, index, real_text):
        """Reveal the real text when hovering over obfuscated text"""
        try:
            self.chat_text.config(state=tk.NORMAL)
            # Delete the obfuscated text
            end_index = f"{index} + {len(real_text)} chars"
            self.chat_text.delete(index, end_index)
            # Insert the real text
            self.chat_text.insert(index, real_text)
            self.chat_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error revealing text: {e}")
    
    def _hide_obfuscated_text(self, index, obfuscated_text):
        """Replace with obfuscated text when mouse leaves"""
        try:
            self.chat_text.config(state=tk.NORMAL)
            # Delete the real text
            end_index = f"{index} + {len(obfuscated_text)} chars"
            self.chat_text.delete(index, end_index)
            # Insert the obfuscated text
            self.chat_text.insert(index, obfuscated_text)
            self.chat_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error hiding text: {e}")
    
    def add_system_message(self, message):
        """Add a system message to the chat area"""
        self.chat_text.config(state=tk.NORMAL)
        
        # Add timestamp
        time_str = time.strftime("%H:%M:%S", time.localtime())
        self.chat_text.insert(tk.END, f"\n[{time_str}] ", "timestamp")
        
        # Add message
        if "encryption" in message.lower() or "protected" in message.lower() or "secure" in message.lower():
            self.chat_text.insert(tk.END, f"{self.icons['lock']} {message}\n", "security")
        else:
            self.chat_text.insert(tk.END, f"{message}\n", "system")
        
        # Scroll to bottom
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)
    
    # Callback methods for P2P node events
    def on_peer_disconnected(self, peer_id):
        """Called when a peer disconnects"""
        self.master.after(0, lambda: self.remove_peer_from_list(peer_id))
        
        # Add system message if in a group with this peer
        if self.current_group is not None and peer_id in self.node.peers:
            username = self.node.peers[peer_id][2]
            self.master.after(0, lambda: self.add_system_message(f"Peer {username} disconnected"))
    
    def on_peer_list_received(self, new_peers):
        """Called when a list of new peers is received"""
        # We don't automatically connect to these peers
        if new_peers:
            peers_info = "\n".join([f"{info[2]} ({info[0]}:{info[1]})" for info in new_peers.values()])
            self.master.after(0, lambda: messagebox.showinfo("Available Peers", 
                                                        f"The following peers are available:\n\n{peers_info}\n\n"
                                                        f"You can connect to them manually by entering their IP and port."))
    
    def on_group_created(self, group_id, group_name, creator_id):
        """Called when a group is created"""
        self.master.after(0, lambda: self.add_group_to_list(group_id))
        
        # Add system message if we're in this group
        if self.current_group == group_id:
            creator_name = "You" if creator_id == self.node.node_id else "Someone"
            self.master.after(0, lambda: self.add_system_message(f"Group '{group_name}' created by {creator_name}"))
    
    def on_group_member_joined(self, group_id, member_id):
        """Called when a member joins a group"""
        # Add system message if we're in this group
        if self.current_group == group_id and member_id in self.node.peers:
            username = self.node.peers[member_id][2]
            self.master.after(0, lambda: self.add_system_message(f"{username} joined the group"))
    
    def on_group_member_left(self, group_id, member_id):
        """Called when a member leaves a group"""
        # Add system message if we're in this group
        if self.current_group == group_id:
            username = "Unknown"
            if member_id == self.node.node_id:
                username = "You"
            elif member_id in self.node.peers:
                username = self.node.peers[member_id][2]
            
            self.master.after(0, lambda: self.add_system_message(f"{username} left the group"))
    
    def on_chat_message_received(self, group_id, message):
        """Called when a chat message is received - FIXED VERSION"""
        # Add to groups list if not already there
        if group_id not in self.group_frames:
            self.master.after(0, lambda: self.add_group_to_list(group_id))
        
        # Add message to UI if we're in this group
        if self.current_group == group_id:
            sender_id = message.get('sender_id')
            content = message.get('content')
            timestamp = message.get('timestamp')
            obfuscated = message.get('obfuscated', False)
            
            sender_name = "Unknown"
            if sender_id == self.node.node_id:
                sender_name = f"{self.node.username} (You)"
            elif sender_id in self.node.peers:
                sender_name = self.node.peers[sender_id][2]
            
            # Check if this is a file message
            if 'file_transfer_id' in message:
                file_transfer_id = message.get('file_transfer_id')
                file_type = message.get('file_type')
                file_size = message.get('file_size')
                
                # Add file to transfers tab
                self.master.after(0, lambda: self.add_transfer_to_list(
                    file_transfer_id, content, file_type, file_size
                ))
                
                # Show message with timestamp and sender
                self.master.after(0, lambda: self.chat_text.config(state=tk.NORMAL))
                if timestamp:
                    time_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
                    self.master.after(0, lambda ts=time_str: self.chat_text.insert(tk.END, "\\n[" + ts + "] ", "timestamp"))
                
                # Add sender name
                tag = "self" if sender_id == self.node.node_id else "other"
                self.master.after(0, lambda sn=sender_name, t=tag: self.chat_text.insert(tk.END, sn + " shared a file:", t))
                self.master.after(0, lambda: self.chat_text.config(state=tk.DISABLED))
                
                # If we have the file data, display it
                if file_transfer_id in self.node.file_transfers and 'file_info' in self.node.file_transfers[file_transfer_id]:
                    file_info = self.node.file_transfers[file_transfer_id]['file_info']
                    if 'data' in file_info:
                        self.master.after(0, lambda: self.display_file(file_info, tag=tag))
                    else:
                        # Request the file if we don't have it and we're not the sender
                        if sender_id != self.node.node_id:
                            self.master.after(0, lambda: self.node.request_file_chunk(file_transfer_id, 0))
                elif sender_id != self.node.node_id:
                    # Create a transfer record and request the file
                    transfer = {
                        'file_info': {
                            'filename': content,
                            'file_type': file_type,
                            'file_size': file_size,
                            'message_id': message.get('message_id')
                        },
                        'sender_id': sender_id,
                        'group_id': group_id,
                        'chunks': [],
                        'received_chunks': 0,
                        'total_chunks': 0
                    }
                    self.node.file_transfers[file_transfer_id] = transfer
                    self.master.after(0, lambda: self.node.request_file_chunk(file_transfer_id, 0))
            else:
                # Regular text message
                self.master.after(0, lambda: self.add_chat_message(
                    sender_id, sender_name, content, timestamp, obfuscated
                ))
    
    def on_group_info_received(self, group_id, group_name, members):
        """Called when group info is received"""
        # Add to groups list if not already there
        if group_id not in self.group_frames:
            self.master.after(0, lambda: self.add_group_to_list(group_id))
    
    def on_file_transfer_created(self, transfer_id, filename, file_type, file_size):
        """Called when a file transfer is created"""
        # Add to transfers list if not already there
        if transfer_id not in self.file_transfers:
            self.master.after(0, lambda: self.add_transfer_to_list(
                transfer_id, filename, file_type, file_size
            ))
    
    def on_file_progress(self, transfer_id, progress):
        """Called when file transfer progress updates"""
        self.master.after(0, lambda: self.update_transfer_progress(transfer_id, progress))
    
    def on_file_received(self, transfer_id, file_info):
        """Called when a complete file is received"""
        # Update progress to 100%
        self.master.after(0, lambda: self.update_transfer_progress(transfer_id, 1.0))
        
        # Add system message if we're in the relevant group
        group_id = self.node.file_transfers[transfer_id].get('group_id')
        if self.current_group == group_id:
            filename = file_info.get('filename', 'file')
            self.master.after(0, lambda: self.add_system_message(f"Received file: {filename}"))
            
            # If this message is currently displayed, update it to show the file
            message_id = file_info.get('message_id')
            if message_id:
                for msg in self.node.groups[group_id]['messages']:
                    if msg.get('message_id') == message_id:
                        # We need to refresh the display
                        self.master.after(0, lambda: self.select_group(group_id))
                        break
    
    def on_file_delivered(self, transfer_id, peer_id):
        """Called when a file is confirmed delivered to a peer"""
        # Update UI to show the file was delivered
        if transfer_id in self.file_transfers:
            filename = self.file_transfers[transfer_id].get('filename', 'file')
            username = "Unknown"
            if peer_id in self.node.peers:
                username = self.node.peers[peer_id][2]
            
            # Add a note to the transfer display
            if transfer_id in self.file_transfers and 'frame' in self.file_transfers[transfer_id]:
                transfer_frame = self.file_transfers[transfer_id]['frame']
                delivered_label = ttk.Label(transfer_frame, text=f"Delivered to {username}", foreground="green")
                delivered_label.pack(side=tk.BOTTOM, fill=tk.X)
    
    
    def on_password_challenge_received(self, peer_id, group_id, challenge_id):
        """Called when a password challenge is received"""
        if group_id in self.node.groups:
            group_name = self.node.groups[group_id]['name']
            self.master.after(0, lambda: self.show_password_challenge_dialog(peer_id, group_id, group_name, challenge_id))
    
    def on_group_access_denied(self, group_id, reason, data):
        """Called when group access is denied"""
        if reason == 'wrong_password':
            attempts_left = data.get('attempts_left', 0)
            self.master.after(0, lambda: tk.messagebox.showerror(
                "Access Denied", 
                f"Incorrect password. {attempts_left} attempts remaining."
            ))
        elif reason == 'banned':
            remaining_time = data.get('remaining_time', 0)
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            self.master.after(0, lambda: tk.messagebox.showerror(
                "Access Denied", 
                f"You have been banned from this group.Time remaining: {minutes}m {seconds}s"
            ))
    def on_close(self):
        """Handle window close event"""
        if self.node is not None:
            self.node.disconnect_all()
        self.master.destroy()


def main():
    """Main function to start the application"""
    root = tk.Tk()
    root.title("EnhancedChatrio")
    
    # Set app icon if available
    try:
        # You would replace this with your actual icon file
        # root.iconbitmap("chatrio_icon.ico")  # On Windows
        pass
    except:
        pass
    
    # Create and start app
    app = ModernChatApp(root)
    
    # Display an intro message
    messagebox.showinfo(
        "EnhancedChatrio v1.0",
        "Welcome to EnhancedChatrio!\n\n"
        "• End-to-end encryption for all communications\n"
        "• Share images, videos, PDFs, and other files\n"
        "• Minecraft-style obfuscated messages\n"
        "• P2P architecture with no central server\n\n"
        "Start by entering your username and port, then click 'Start Node'"
    )
    
    # Start main loop
    root.mainloop()


if __name__ == "__main__":
    main()