# NTFS Tweaks
fsutil 8dot3name set 1
fsutil behavior set disableCompression 1
fsutil behavior set disableLastAccess 1

# Disable Memory Compression
Disable-MMAgent -mc
