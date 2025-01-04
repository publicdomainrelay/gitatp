import io
import shutil
import zipfile

# Create a minimal PNG header
PNG_HEADER = (
    b'\x89PNG\r\n\x1a\n'  # PNG signature
    b'\x00\x00\x00\r'     # IHDR chunk length
    b'IHDR'               # IHDR chunk type
    b'\x00\x00\x00\x01'   # Width: 1
    b'\x00\x00\x00\x01'   # Height: 1
    b'\x08'               # Bit depth: 8
    b'\x02'               # Color type: Truecolor
    b'\x00'               # Compression method
    b'\x00'               # Filter method
    b'\x00'               # Interlace method
    b'\x90wS\xde'         # CRC
    b'\x00\x00\x00\x0a'   # IDAT chunk length
    b'IDAT'               # IDAT chunk type
    b'\x78\x9c\x63\x60\x00\x00\x00\x02\x00\x01'  # Compressed data
    b'\x02\x7e\xe5\x45'   # CRC
    b'\x00\x00\x00\x00'   # IEND chunk length
    b'IEND'               # IEND chunk type
    b'\xaeB`\x82'         # CRC
)

def extract_zip_from_png(png_zip_data):
    global PNG_HEADER
    return png_zip_data[len(PNG_HEADER):]

# Extract zip archive containing the internal files
def extract_zip_of_files(repo_path, blob, files):
    zip_buffer = io.BytesIO(blob)
    with zipfile.ZipFile(zip_buffer, 'r', zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            local_filepath = repo_path.joinpath(file)
            local_filepath.parent.mkdir(parents=True, exist_ok=True)
            local_filepath.write_bytes(b"")
            local_filepath.chmod(0o600)
            with zipf.open(file) as zip_filobj, open(local_filepath, "wb") as local_fileobj:
                shutil.copyfileobj(zip_filobj, local_fileobj)

# Create a zip archive containing the internal files
def create_zip_of_files(repo_path, files):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            arcname = str(file.relative_to(repo_path))
            zipf.write(file, arcname=arcname)
    zip_buffer.seek(0)
    return zip_buffer.read()

# Create a PNG image that also contains the zip archive
def create_png_with_zip(zip_data):
    global PNG_HEADER
    # Combine the PNG header and the zip data
    png_zip_data = PNG_HEADER + zip_data
    return png_zip_data
