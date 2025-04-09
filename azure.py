import os
from azure.storage.blob import BlobServiceClient

# Azure Storage details
CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=talkwithdocuments;AccountKey=DVCbSfiaUgSawGnwEfRt3ZHe3s7EeKYiLbAxlHibkLUv98hRjJ70ufM7cPIVJL6bNZgVtvUad00z+ASt4RT+NA==;EndpointSuffix=core.windows.net"
CONTAINER_NAME = "csai"
LOCAL_FOLDER_PATH = "/home/azureuser/csai"

def upload_folder_to_blob(storage_connection_string, container_name, local_folder):
    # Create a BlobServiceClient
    blob_service_client = BlobServiceClient.from_connection_string(storage_connection_string)
    
    # Get a container client
    container_client = blob_service_client.get_container_client(container_name)
    
    # Ensure container exists
    try:
        container_client.create_container()
    except Exception as e:
        print("Container already exists.")

    # Walk through the folder and upload files
    for root, dirs, files in os.walk(local_folder):
        for file in files:
            local_file_path = os.path.join(root, file)
            blob_path = os.path.relpath(local_file_path, local_folder).replace("\\", "/")  # Ensure proper path formatting
            
            print(f"Uploading {local_file_path} to {blob_path}...")

            with open(local_file_path, "rb") as data:
                blob_client = container_client.get_blob_client(blob_path)
                blob_client.upload_blob(data, overwrite=True)

    print("Upload completed!")

if __name__ == "__main__":
    upload_folder_to_blob(CONNECTION_STRING, CONTAINER_NAME, LOCAL_FOLDER_PATH)
