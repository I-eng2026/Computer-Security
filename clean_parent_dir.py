import os

def find_and_delete_duplicate_files_in_parent():
    """
    Lists files in the current directory and deletes files with the same name
    in the parent directory after user confirmation.
    """
    current_dir = os.getcwd()
    parent_dir = os.path.dirname(current_dir)

    print(f"Current directory: {current_dir}")
    print(f"Parent directory: {parent_dir}")

    try:
        # Get list of files in the current directory (not directories)
        files_in_current_dir = [f for f in os.listdir(current_dir) if os.path.isfile(os.path.join(current_dir, f))]

        if not files_in_current_dir:
            print("No files found in the current directory.")
            return

        print("\nFiles in the current directory:")
        for f in files_in_current_dir:
            print(f"  - {f}")

        # Find which of these files also exist in the parent directory
        files_to_delete = []
        for filename in files_in_current_dir:
            parent_file_path = os.path.join(parent_dir, filename)
            if os.path.isfile(parent_file_path):
                files_to_delete.append(parent_file_path)

        if not files_to_delete:
            print("\nNo files from the current directory were found in the parent directory. Nothing to delete.")
            return

        print("\nThe following files exist in the parent directory and will be DELETED:")
        for f_path in files_to_delete:
            print(f"  - {f_path}")

        # Ask for confirmation
        confirm = input("\nAre you sure you want to delete these files? (yes/no): ").lower()

        if confirm == 'yes':
            deleted_count = 0
            for f_path in files_to_delete:
                try:
                    os.remove(f_path)
                    print(f"Deleted: {f_path}")
                    deleted_count += 1
                except OSError as e:
                    print(f"Error deleting file {f_path}: {e}")
            print(f"\nDeletion complete. {deleted_count} file(s) deleted.")
        else:
            print("\nDeletion cancelled by user.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    find_and_delete_duplicate_files_in_parent()
