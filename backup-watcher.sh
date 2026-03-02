#!/bin/bash
# Blog data backup watcher
# Monitors /data/blog.dat and creates timestamped backups on change

DATA_FILE="/data/blog.dat"
BACKUP_DIR="/backups"
GIT_DIR="/backups/git-history"

# Initialize git repo if it doesn't exist
if [ ! -d "$GIT_DIR/.git" ]; then
    mkdir -p "$GIT_DIR"
    cd "$GIT_DIR"
    git init
    git config user.email "backup@localhost"
    git config user.name "Blog Backup Bot"
    echo "Initialized git repo for blog backups"
fi

# Fix ownership warning for mounted volumes
git config --global --add safe.directory "$GIT_DIR"

# Initial backup on startup
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
cp "$DATA_FILE" "$BACKUP_DIR/blog-${TIMESTAMP}.dat"
cp "$DATA_FILE" "$GIT_DIR/blog.dat"
cd "$GIT_DIR"
git add blog.dat
git commit -m "Backup: ${TIMESTAMP}" 2>/dev/null || true
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Initial backup created: blog-${TIMESTAMP}.dat"

# Watch for changes
inotifywait -m -e modify,close_write "$DATA_FILE" --format '%T' --timefmt '%Y%m%d-%H%M%S' |
while read TIMESTAMP; do
    # Create timestamped backup
    cp "$DATA_FILE" "$BACKUP_DIR/blog-${TIMESTAMP}.dat"

    # Git commit
    cp "$DATA_FILE" "$GIT_DIR/blog.dat"
    cd "$GIT_DIR"
    git add blog.dat
    git commit -m "Backup: ${TIMESTAMP}" 2>/dev/null

    # Keep only last 50 timestamped backups (cleanup old ones)
    cd "$BACKUP_DIR"
    ls -t blog-*.dat | tail -n +51 | xargs -r rm

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup created: blog-${TIMESTAMP}.dat (total: $(ls -1 blog-*.dat 2>/dev/null | wc -l) backups)"
done
