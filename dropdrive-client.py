#!/usr/bin/env python3

import argparse
import sys
import os
import json
import pycurl
import io
from typing import Optional, Dict, Any
from pathlib import Path

class DropDriveClient:
    def __init__(self):
        self.base_url = "https://dropdrive.co"
        self.config_file = Path.home() / '.dropdrive_config.json'
        self.headers = {}
        self.load_config()
    
    def load_config(self):
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.user_id = config.get('user_id')
                    self.login_id = config.get('login_id')
                    if self.token:
                        self.headers['Authorization'] = f'Bearer {self.token}'
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
        self.token = None
        self.user_id = None
        self.login_id = None
        if 'Authorization' in self.headers:
            del self.headers['Authorization']
        if self.config_file.exists():
            self.config_file.unlink()
    
    def is_authenticated(self) -> bool:
        return self.token is not None
    
    def _make_request(self, url: str, method: str = 'GET', data: bytes = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
        buffer = io.BytesIO()
        c = pycurl.Curl()
        
        try:
            c.setopt(c.URL, url)
            c.setopt(c.WRITEDATA, buffer)
            
            req_headers = self.headers.copy()
            if headers:
                req_headers.update(headers)
            
            if req_headers:
                header_list = [f"{k}: {v}" for k, v in req_headers.items()]
                c.setopt(c.HTTPHEADER, header_list)
            
            if method == 'POST':
                c.setopt(c.POST, 1)
                if data:
                    c.setopt(c.POSTFIELDS, data)
            elif method == 'DELETE':
                c.setopt(c.CUSTOMREQUEST, 'DELETE')
                if data:
                    c.setopt(c.POSTFIELDS, data)
            
            c.perform()
            status_code = c.getinfo(c.RESPONSE_CODE)
            c.close()
            
            response_data = buffer.getvalue()
            if response_data:
                return {
                    'status_code': status_code,
                    'data': json.loads(response_data.decode())
                }
            return {'status_code': status_code, 'data': {}}
            
        except Exception as e:
            c.close()
            raise e
    
    def _post_json(self, url: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(json_data).encode()
        headers = {'Content-Type': 'application/json'}
        return self._make_request(url, 'POST', data, headers)
    
    def _post_multipart(self, url: str, form_data: Dict[str, Any], files: Dict[str, tuple] = None) -> Dict[str, Any]:
        boundary = f'----formdata-{os.urandom(16).hex()}'
        data = b''
        
        for key, value in form_data.items():
            data += f'--{boundary}\r\n'.encode()
            data += f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
            data += f'{value}\r\n'.encode()
        
        if files:
            for key, (filename, file_data) in files.items():
                data += f'--{boundary}\r\n'.encode()
                data += f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode()
                data += b'Content-Type: application/octet-stream\r\n\r\n'
                data += file_data
                data += b'\r\n'
        
        data += f'--{boundary}--\r\n'.encode()
        
        headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}
        return self._make_request(url, 'POST', data, headers)
    
    def _delete_json(self, url: str, json_data: Dict[str, Any] = None) -> Dict[str, Any]:
        data = None
        headers = {}
        if json_data:
            data = json.dumps(json_data).encode()
            headers['Content-Type'] = 'application/json'
        return self._make_request(url, 'DELETE', data, headers)
    
    def login(self, login_id: str, password: str) -> bool:
        try:
            response = self._post_json(
                f"{self.base_url}/api/auth/login",
                {'loginId': login_id, 'password': password}
            )
            
            if response['status_code'] == 200:
                data = response['data']
                if data.get('success'):
                    self.token = data.get('token')
                    self.user_id = str(data['user']['id'])
                    self.login_id = data['user']['loginId']
                    self.headers['Authorization'] = f'Bearer {self.token}'
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
                print(f"Login failed: HTTP {response['status_code']}")
                error_msg = response['data'].get('error', 'Unknown error')
                print(f"Error: {error_msg}")
                return False
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def logout(self) -> bool:
        self.clear_config()
        print("Logged out successfully!")
        return True
    
    def upload_file(self, file_path: str, use_user_account: bool = False) -> bool:
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
            
            init_response = self._post_json(
                f"{self.base_url}/api/upload/init",
                init_data
            )
            
            if init_response['status_code'] != 200:
                print(f"Failed to initialize upload: HTTP {init_response['status_code']}")
                error_msg = init_response['data'].get('error', 'Unknown error')
                print(f"Error: {error_msg}")
                return False
            
            init_result = init_response['data']
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
                    
                    response = self._post_multipart(
                        f"{self.base_url}/api/upload",
                        form_data,
                        files
                    )
                    
                    if response['status_code'] != 200:
                        print(f"Upload failed at chunk {chunk_index}: HTTP {response['status_code']}")
                        error_msg = response['data'].get('error', 'Unknown error')
                        print(f"Error: {error_msg}")
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
        if not self.is_authenticated():
            print("Error: Must be logged in to delete files")
            return False
        
        try:
            response = self._make_request(
                f"{self.base_url}/api/delete/{file_id}?userId={self.user_id}",
                'DELETE'
            )
            
            if response['status_code'] == 200:
                data = response['data']
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
                print(f"Delete failed: HTTP {response['status_code']}")
                error_msg = response['data'].get('error', 'Unknown error')
                print(f"Error: {error_msg}")
                return False
                
        except Exception as e:
            print(f"Delete failed: {e}")
            return False
    
    def delete_file_with_token(self, file_id: str, owner_token: str) -> bool:
        try:
            response = self._delete_json(
                f"{self.base_url}/api/delete/{file_id}",
                {'ownerToken': owner_token}
            )
            
            if response['status_code'] == 200:
                data = response['data']
                if data.get('success'):
                    print("File deleted successfully!")
                    return True
                else:
                    print(f"Delete failed: {data.get('error', 'Unknown error')}")
                    return False
            else:
                print(f"Delete failed: HTTP {response['status_code']}")
                error_msg = response['data'].get('error', 'Unknown error')
                print(f"Error: {error_msg}")
                return False
                
        except Exception as e:
            print(f"Delete failed: {e}")
            return False
    
    def list_files(self) -> bool:
        if not self.is_authenticated():
            print("Error: Must be logged in to list files")
            return False
        
        try:
            response = self._make_request(f"{self.base_url}/api/auth/user/files")
            
            if response['status_code'] == 200:
                data = response['data']
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
                print(f"Failed to list files: HTTP {response['status_code']}")
                error_msg = response['data'].get('error', 'Unknown error')
                print(f"Error: {error_msg}")
                return False
                
        except Exception as e:
            print(f"Failed to list files: {e}")
            return False
    
    def _format_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    def validate_files(self, file_paths: list) -> tuple:
        valid_files = []
        invalid_files = []
        total_size = 0
        
        for file_path in file_paths:
            path = Path(file_path)
            if not path.exists():
                invalid_files.append((file_path, "File does not exist"))
            elif not path.is_file():
                invalid_files.append((file_path, "Not a file"))
            else:
                try:
                    size = path.stat().st_size
                    valid_files.append((str(path), size))
                    total_size += size
                except Exception as e:
                    invalid_files.append((file_path, f"Cannot read file: {e}"))
        
        return valid_files, invalid_files, total_size


def main():
    parser = argparse.ArgumentParser(
        description="DropDrive CLI Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dropdrive-client.py upload document.pdf
  python3 dropdrive-client.py upload file1.txt file2.pdf file3.jpg
  python3 dropdrive-client.py upload document.pdf --user
  python3 dropdrive-client.py upload *.txt --user
  python3 dropdrive-client.py login myloginid mypassword
  python3 dropdrive-client.py logout
  python3 dropdrive-client.py delete abc123def456
  python3 dropdrive-client.py delete-token abc123def456 ownertoken123
  python3 dropdrive-client.py listfiles
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    upload_parser = subparsers.add_parser('upload', help='Upload files')
    upload_parser.add_argument('file_paths', nargs='+', help='Paths to the files to upload')
    upload_parser.add_argument('--user', action='store_true', help='Upload as authenticated user (requires login)')
    
    login_parser = subparsers.add_parser('login', help='Login to DropDrive')
    login_parser.add_argument('login_id', help='Your login ID')
    login_parser.add_argument('password', help='Your password, same as login ID')
    
    logout_parser = subparsers.add_parser('logout', help='Logout from DropDrive')
    
    delete_parser = subparsers.add_parser('delete', help='Delete a file')
    delete_parser.add_argument('file_id', help='ID of the file to delete')
    
    delete_token_parser = subparsers.add_parser('delete-token', help='Delete a file using owner token')
    delete_token_parser.add_argument('file_id', help='ID of the file to delete')
    delete_token_parser.add_argument('owner_token', help='Owner token for the file')
    
    list_parser = subparsers.add_parser('listfiles', help='List your uploaded files')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    client = DropDriveClient()
    
    try:
        if args.command == 'upload':
            valid_files, invalid_files, total_size = client.validate_files(args.file_paths)
            
            if invalid_files:
                print("Invalid files found:")
                for file_path, error in invalid_files:
                    print(f"  {file_path}: {error}")
                if not valid_files:
                    return 1
                print()
            
            total_files = len(valid_files)
            if total_files == 0:
                print("No valid files to upload")
                return 1
            
            if total_files > 1:
                print(f"Uploading {total_files} files (Total size: {client._format_size(total_size)})...")
            
            success_count = 0
            for i, (file_path, file_size) in enumerate(valid_files, 1):
                if total_files > 1:
                    print(f"\n[{i}/{total_files}] Processing: {Path(file_path).name} ({client._format_size(file_size)})")
                
                if client.upload_file(file_path, args.user):
                    success_count += 1
                else:
                    print(f"Failed to upload: {file_path}")
            
            if total_files > 1:
                print(f"\nUpload: {success_count}/{total_files} files uploaded successfully")
            
            success = success_count == total_files
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
