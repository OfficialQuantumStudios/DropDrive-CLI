#!/usr/bin/env python3
"""
DropDrive CLI Client

A command-line interface for the DropDrive file sharing platform.
"""

import argparse
import sys
import os
import json
import requests
from typing import Optional, Dict, Any
from pathlib import Path

class DropDriveClient:
    def __init__(self):
        self.base_url = "https://dropdrive.co"
        self.config_file = Path.home() / '.dropdrive_config.json'
        self.session = requests.Session()
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.user_id = config.get('user_id')
                    self.login_id = config.get('login_id')
                    if self.token:
                        self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            else:
                self.token = None
                self.user_id = None
                self.login_id = None
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            self.token = None
            self.user_id = None
            self.login_id = None
    
    def save_config(self):
        """Save configuration to file."""
        try:
            config = {
                'token': self.token,
                'user_id': self.user_id,
                'login_id': self.login_id
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Warning: Could not save config: {e}")
    
    def clear_config(self):
        """Clear stored configuration."""
        self.token = None
        self.user_id = None
        self.login_id = None
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
        if self.config_file.exists():
            self.config_file.unlink()
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.token is not None
    
    def login(self, login_id: str, password: str) -> bool:
        """Login to DropDrive."""
        try:
            response = self.session.post(
                f"{self.base_url}/api/auth/login",
                json={'loginId': login_id, 'password': password}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.token = data.get('token')
                    self.user_id = str(data['user']['id'])
                    self.login_id = data['user']['loginId']
                    self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                    self.save_config()
                    
                    if data.get('requiresTwoFA'):
                        print("Login successful! Note: 2FA is enabled on your account.")
                        print("Some operations may require 2FA verification.")
                    else:
                        print("Login successful!")
                    return True
                else:
                    print(f"Login failed: {data.get('error', 'Unknown error')}")
                    return False
            else:
                print(f"Login failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error: {error_data.get('error', 'Unknown error')}")
                except:
                    pass
                return False
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def logout(self) -> bool:
        """Logout from DropDrive."""
        self.clear_config()
        print("Logged out successfully!")
        return True
    
    def upload_file(self, file_path: str, use_user_account: bool = False) -> bool:
        """Upload a file to DropDrive."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            print(f"Error: File '{file_path}' does not exist")
            return False
        
        if not file_path.is_file():
            print(f"Error: '{file_path}' is not a file")
            return False
        
        if use_user_account and not self.is_authenticated():
            print("Error: Must be logged in to upload as user")
            return False
        
        try:
            file_size = file_path.stat().st_size
            file_name = file_path.name
            
            print(f"Initializing upload for '{file_name}' ({file_size} bytes)...")
            
            init_data = {
                'fileName': file_name,
                'fileSize': file_size
            }
            
            if use_user_account and self.user_id:
                init_data['userId'] = self.user_id
            
            init_response = self.session.post(
                f"{self.base_url}/api/upload/init",
                json=init_data
            )
            
            if init_response.status_code != 200:
                print(f"Failed to initialize upload: HTTP {init_response.status_code}")
                try:
                    error_data = init_response.json()
                    print(f"Error: {error_data.get('error', 'Unknown error')}")
                except:
                    pass
                return False
            
            init_result = init_response.json()
            if not init_result.get('success'):
                print(f"Failed to initialize upload: {init_result.get('error', 'Unknown error')}")
                return False
            
            file_id = init_result['fileId']
            owner_token = init_result.get('ownerToken', '')
            total_chunks = init_result['totalChunks']
            chunk_size = init_result['chunkSize']
            
            print(f"Server assigned file ID: {file_id}")
            if owner_token:
                print(f"Generated owner token for anonymous upload")
            else:
                print(f"Upload linked to user account (no owner token needed)")
            print(f"Uploading in {total_chunks} chunks of {chunk_size} bytes each...")
            
            with open(file_path, 'rb') as f:
                for chunk_index in range(total_chunks):
                    chunk_data = f.read(chunk_size)
                    
                    form_data = {
                        'fileId': file_id,
                        'chunkIndex': str(chunk_index),
                        'totalChunks': str(total_chunks),
                        'fileName': file_name,
                        'ownerToken': owner_token
                    }
                    
                    if use_user_account and self.user_id:
                        form_data['userId'] = self.user_id
                    
                    files = {'chunk': (f'chunk_{chunk_index}', chunk_data)}
                    
                    response = self.session.post(
                        f"{self.base_url}/api/upload",
                        data=form_data,
                        files=files
                    )
                    
                    if response.status_code != 200:
                        print(f"Upload failed at chunk {chunk_index}: HTTP {response.status_code}")
                        try:
                            error_data = response.json()
                            print(f"Error: {error_data.get('error', 'Unknown error')}")
                        except:
                            pass
                        return False
                    
                    progress = ((chunk_index + 1) / total_chunks) * 100
                    print(f"Progress: {progress:.1f}%", end='\r')
            
            print("\nUpload completed successfully!")
            print(f"File ID: {file_id}")
            print(f"Download URL: https://dropdrive.co/file/{file_id}")
            if owner_token:
                print(f"Owner Token: {owner_token}")
                print("Note: Keep the owner token safe for file management")
            else:
                print("File is linked to your user account")
            return True
            
        except Exception as e:
            print(f"Upload failed: {e}")
            return False
    
    def delete_file(self, file_id: str) -> bool:
        """Delete a file from DropDrive (user files only)."""
        if not self.is_authenticated():
            print("Error: Must be logged in to delete files")
            return False
        
        try:
            response = self.session.delete(
                f"{self.base_url}/api/delete/{file_id}?userId={self.user_id}"
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    print("File deleted successfully!")
                    return True
                elif data.get('requiresTwoFA'):
                    print("Error: This operation requires 2FA verification.")
                    print("Please use the web interface to complete 2FA and try again.")
                    return False
                else:
                    print(f"Delete failed: {data.get('error', 'Unknown error')}")
                    return False
            else:
                print(f"Delete failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error: {error_data.get('error', 'Unknown error')}")
                except:
                    pass
                return False
                
        except Exception as e:
            print(f"Delete failed: {e}")
            return False
    
    def delete_file_with_token(self, file_id: str, owner_token: str) -> bool:
        """Delete a file using owner token (for anonymous uploads)."""
        try:
            response = self.session.delete(
                f"{self.base_url}/api/delete/{file_id}",
                json={'ownerToken': owner_token}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    print("File deleted successfully!")
                    return True
                else:
                    print(f"Delete failed: {data.get('error', 'Unknown error')}")
                    return False
            else:
                print(f"Delete failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error: {error_data.get('error', 'Unknown error')}")
                except:
                    pass
                return False
                
        except Exception as e:
            print(f"Delete failed: {e}")
            return False
    
    def list_files(self) -> bool:
        """List user's files."""
        if not self.is_authenticated():
            print("Error: Must be logged in to list files")
            return False
        
        try:
            response = self.session.get(f"{self.base_url}/api/auth/user/files")
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    files = data.get('files', [])
                    
                    if not files:
                        print("No files found.")
                        return True
                    
                    print(f"\nFound {len(files)} file(s):\n")
                    print(f"{'File ID':<32} {'Name':<30} {'Size':<12} {'Upload Date':<20} {'Downloads':<10}")
                    print("-" * 110)
                    
                    for file in files:
                        size_str = self._format_size(file['size'])
                        upload_date = file['uploadedAt'][:19].replace('T', ' ')
                        
                        print(f"{file['id']:<32} {file['name'][:29]:<30} {size_str:<12} {upload_date:<20} {file['downloadCount']:<10}")
                    
                    return True
                else:
                    print(f"Failed to list files: {data.get('error', 'Unknown error')}")
                    return False
            else:
                print(f"Failed to list files: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error: {error_data.get('error', 'Unknown error')}")
                except:
                    pass
                return False
                
        except Exception as e:
            print(f"Failed to list files: {e}")
            return False
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"


def main():
    parser = argparse.ArgumentParser(
        description="DropDrive CLI Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dropdrive-client.py upload document.pdf
  python3 dropdrive-client.py upload document.pdf --user
  python3 dropdrive-client.py login myloginid mypassword
  python3 dropdrive-client.py logout
  python3 dropdrive-client.py delete abc123def456
  python3 dropdrive-client.py delete-token abc123def456 ownertoken123
  python3 dropdrive-client.py listfiles
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload a file')
    upload_parser.add_argument('file_path', help='Path to the file to upload')
    upload_parser.add_argument('--user', action='store_true', help='Upload as authenticated user (requires login)')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Login to DropDrive')
    login_parser.add_argument('login_id', help='Your login ID')
    login_parser.add_argument('password', help='Your password, same as login ID')
    
    # Logout command
    logout_parser = subparsers.add_parser('logout', help='Logout from DropDrive')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a file')
    delete_parser.add_argument('file_id', help='ID of the file to delete')
    
    # Delete with token command
    delete_token_parser = subparsers.add_parser('delete-token', help='Delete a file using owner token')
    delete_token_parser.add_argument('file_id', help='ID of the file to delete')
    delete_token_parser.add_argument('owner_token', help='Owner token for the file')
    
    # List files command
    list_parser = subparsers.add_parser('listfiles', help='List your uploaded files')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    client = DropDriveClient()
    
    try:
        if args.command == 'upload':
            success = client.upload_file(args.file_path, args.user)
        elif args.command == 'login':
            success = client.login(args.login_id, args.password)
        elif args.command == 'logout':
            success = client.logout()
        elif args.command == 'delete':
            success = client.delete_file(args.file_id)
        elif args.command == 'delete-token':
            success = client.delete_file_with_token(args.file_id, args.owner_token)
        elif args.command == 'listfiles':
            success = client.list_files()
        else:
            print(f"Unknown command: {args.command}")
            return 1
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
