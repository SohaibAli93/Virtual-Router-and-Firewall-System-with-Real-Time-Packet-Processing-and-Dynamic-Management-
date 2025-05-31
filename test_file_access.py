import os
import json

def test_file_access():
    filename = "routing_table.json"
    print(f"Testing file access for: {filename}")
    
    # Get absolute path
    abs_path = os.path.abspath(filename)
    print(f"Absolute path: {abs_path}")
    
    # Check if file exists
    if os.path.exists(abs_path):
        print(f"File exists: Yes")
        print(f"File size: {os.path.getsize(abs_path)} bytes")
        print(f"Read permission: {os.access(abs_path, os.R_OK)}")
        print(f"Write permission: {os.access(abs_path, os.W_OK)}")
        
        # Try to read the file
        try:
            with open(abs_path, 'r') as f:
                data = json.load(f)
                print(f"File content loaded successfully")
                print(f"Number of routes: {len(data.get('routes', []))}")
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        print(f"File does not exist")
        
        # Check if directory is writable
        dir_path = os.path.dirname(abs_path)
        print(f"Directory path: {dir_path}")
        print(f"Directory write permission: {os.access(dir_path, os.W_OK)}")
    
    # Try to write to the file
    print("\nAttempting to write test data...")
    try:
        # Make a backup first
        if os.path.exists(abs_path):
            backup_path = abs_path + ".backup"
            with open(abs_path, 'r') as src, open(backup_path, 'w') as dst:
                dst.write(src.read())
            print(f"Backup created at: {backup_path}")
        
        # Write test data
        test_data = {"test": "data", "timestamp": "test_write"}
        with open(abs_path, 'w') as f:
            json.dump(test_data, f, indent=4)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        print("Test write successful")
        
        # Verify the write
        with open(abs_path, 'r') as f:
            read_data = json.load(f)
            if read_data.get("test") == "data":
                print("Data verification successful")
            else:
                print("Data verification failed")
                
        # Restore the backup
        if os.path.exists(backup_path):
            with open(backup_path, 'r') as src, open(abs_path, 'w') as dst:
                dst.write(src.read())
            print("Original file restored from backup")
            
    except Exception as e:
        print(f"Error writing to file: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    test_file_access() 