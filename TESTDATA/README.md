# Test Data

This directory contains sample LIME memory dumps for testing the Linux Memory Parser tool.

## File Format

The files in this directory are compressed LIME memory dumps. The following compression formats are used:

- `.lime.gz` - Gzip compressed
- `.lime.xz` - XZ compressed
- `.lime.bz2` - Bzip2 compressed
- `.lime.7z` - 7-Zip compressed

## Usage

Before using these files with the Linux Memory Parser tool, you need to decompress them:

```bash
# For gzip compressed files
gunzip sample.lime.gz

# For xz compressed files
unxz sample.lime.xz

# For bzip2 compressed files
bunzip2 sample.lime.bz2

# For 7z compressed files
7z x sample.lime.7z
```

## Git Repository

The .gitignore file is configured to:
- Ignore uncompressed LIME files (`*.lime`)
- Allow compressed LIME files to be stored in the repository

This approach allows us to store test data efficiently while keeping the repository size manageable.