# Determine the service_id
SERVICE_ID=`fastly service list -j | jq -r '.[] | select(.Name=="training_zip_phishing").ID'`

# Build and upload the wasm file
echo "Building and uploading to service_id: $SERVICE_ID"
echo "------------------------------------------------------------"
fastly compute publish --service-id=$SERVICE_ID