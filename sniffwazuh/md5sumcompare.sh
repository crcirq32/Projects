#!/usr/bin/env bash

###############################################################################
# Debian Package and Host Integrity Report
#
# Checks package-managed files and several common persistence/escalation areas.
#
# Important:
#   - MD5 failures indicate that a package-managed file differs from its
#     installed package checksum.
#   - A finding is not automatically malicious. Updates, local administration,
#     locally compiled software, and configuration changes can be legitimate.
#   - Run as root for the most complete results.
###############################################################################

set +e

INFO_DIR="/var/lib/dpkg/info"

# Preserve the original user when run with sudo.
TARGET_USER="${SUDO_USER:-$USER}"
DESKTOP="/home/$TARGET_USER/Desktop"

TIMESTAMP=$(date '+%Y_%m_%d_%H_%M_%S')
REPORT="$DESKTOP/md5compare.$TIMESTAMP"

WORKDIR=$(mktemp -d)

HASHES="$WORKDIR/hashes"
MODIFIED="$WORKDIR/modified"
MISSING="$WORKDIR/missing"
UNREADABLE="$WORKDIR/unreadable"

cleanup() {
    rm -rf "$WORKDIR"
}

trap cleanup EXIT

# Make sure the requested output directory exists.
if [[ ! -d "$DESKTOP" ]]; then
    DESKTOP="$PWD"
    REPORT="$DESKTOP/md5compare.$TIMESTAMP"
fi

###############################################################################
# Helper functions
###############################################################################

section() {
    {
        echo
        echo "###############################################################################"
        echo "$1"
        echo "###############################################################################"
        echo "$2"
        echo
    } >> "$REPORT"
}

run_command() {
    local description="$1"
    shift

    {
        echo "Command: $*"
        echo
        "$@"
        local status=$?

        if (( status != 0 )); then
            echo
            echo "[Command exited with status $status]"
        fi
    } >> "$REPORT" 2>&1
}

###############################################################################
# Report header
###############################################################################

{
    echo "===============================================================================" 
    echo "DEBIAN PACKAGE AND HOST INTEGRITY REPORT"
    echo "===============================================================================" 
    echo
    echo "Generated:       $(date)"
    echo "Hostname:        $(hostname 2>/dev/null)"
    echo "User:            ${TARGET_USER:-unknown}"
    echo "Effective user:  $(id -un 2>/dev/null)"
    echo "Kernel:          $(uname -sr 2>/dev/null)"
    echo "Report file:     $REPORT"
    echo
    echo "Interpretation:"
    echo "  Modified files differ from the package-recorded MD5 checksum."
    echo "  Missing files were expected by a package but were not found."
    echo "  Unreadable files could not be completely checked."
    echo "  Other findings require review and comparison with a known-good baseline."
    echo
} > "$REPORT"

###############################################################################
# Package checksum verification
###############################################################################

section \
"1. PACKAGE CHECKSUM VERIFICATION" \
"Checks files recorded in /var/lib/dpkg/info/*.md5sums against their installed contents."

checksum_lists=0
checksum_entries=0

for checksum_file in "$INFO_DIR"/*.md5sums; do
    [[ -f "$checksum_file" ]] || continue

    ((checksum_lists++))

    # Count checksum entries.
    entries=$(awk '
        /^[0-9a-fA-F]{32}[[:space:]]/ { count++ }
        END { print count + 0 }
    ' "$checksum_file")

    checksum_entries=$((checksum_entries + entries))

    # md5sum entries in Debian package lists are relative to /.
    result=$(
        cd / &&
        md5sum --check --quiet "$checksum_file" 2>&1
    )

    [[ -z "$result" ]] && continue

    while IFS= read -r line; do
        case "$line" in
            *": FAILED")
                echo "$line" >> "$MODIFIED"
                ;;
            *"FAILED open or read"*)
                echo "$line" >> "$UNREADABLE"
                ;;
            *"No such file or directory"*)
                echo "$line" >> "$MISSING"
                ;;
            *)
                echo "$line" >> "$UNREADABLE"
                ;;
        esac
    done <<< "$result"
done

{
    echo "Checksum lists checked: $checksum_lists"
    echo "Checksum entries checked: $checksum_entries"
    echo

    echo "MODIFIED FILES"
    echo "--------------"
    if [[ -s "$MODIFIED" ]]; then
        cat "$MODIFIED"
    else
        echo "None detected."
    fi
    echo

    echo "MISSING FILES"
    echo "-------------"
    if [[ -s "$MISSING" ]]; then
        cat "$MISSING"
    else
        echo "None detected."
    fi
    echo

    echo "UNREADABLE OR UNCHECKED FILES"
    echo "-----------------------------"
    if [[ -s "$UNREADABLE" ]]; then
        cat "$UNREADABLE"
    else
        echo "None detected."
    fi
} >> "$REPORT"

###############################################################################
# Duplicate/shared MD5 hashes
###############################################################################

section \
"2. SHARED MD5 HASH VALUES" \
"Shows different package-listed paths that have identical MD5 values. Shared hashes are often legitimate."

for checksum_file in "$INFO_DIR"/*.md5sums; do
    [[ -f "$checksum_file" ]] || continue

    awk -v source="$checksum_file" '
        /^[0-9a-fA-F]{32}[[:space:]]/ {
            hash = $1
            file = $0
            sub(/^[^[:space:]]+[[:space:]]+/, "", file)
            print hash "\t" source "\t" file
        }
    ' "$checksum_file" >> "$HASHES"
done

duplicate_hashes=$(
    cut -f1 "$HASHES" 2>/dev/null |
    sort |
    uniq -d
)

if [[ -n "$duplicate_hashes" ]]; then
    while IFS= read -r hash; do
        echo "MD5: $hash" >> "$REPORT"

        awk -F '\t' -v wanted="$hash" '
            $1 == wanted {
                print "  File:   " $3
                print "  Source: " $2
            }
        ' "$HASHES" >> "$REPORT"

        echo >> "$REPORT"
    done <<< "$duplicate_hashes"
else
    echo "No duplicate/shared hash values found." >> "$REPORT"
fi

###############################################################################
# Package database status
###############################################################################

section \
"3. PACKAGE DATABASE STATUS" \
"Lists packages whose dpkg status is not the normal installed state."

abnormal_packages=$(
    dpkg-query -W -f='${binary:Package}\t${Status}\n' 2>/dev/null |
    awk '$2 != "ok" || $3 != "installed"'
)

if [[ -n "$abnormal_packages" ]]; then
    echo "$abnormal_packages" >> "$REPORT"
else
    echo "No abnormal package states detected." >> "$REPORT"
fi

###############################################################################
# SUID and SGID files
###############################################################################

section \
"4. SUID AND SGID FILES" \
"Lists files that execute with the file owner's or group owner's privileges. Review unexpected additions carefully."

find / \
    -xdev \
    -type f \
    \( -perm -4000 -o -perm -2000 \) \
    -printf '%m %u:%g %p\n' \
    2>/dev/null >> "$REPORT"

###############################################################################
# File capabilities
###############################################################################

section \
"5. LINUX FILE CAPABILITIES" \
"Lists files with capabilities that can grant privileged actions without SUID."

if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null >> "$REPORT"
else
    echo "getcap is not installed; capability scan unavailable." >> "$REPORT"
fi

###############################################################################
# Unowned files
###############################################################################

section \
"6. FILES NOT OWNED BY AN INSTALLED PACKAGE" \
"Lists files in common system directories that dpkg does not associate with a package."

find /usr /bin /sbin /lib /lib64 \
    -xdev \
    -type f \
    -print0 \
    2>/dev/null |
while IFS= read -r -d '' file; do
    if ! dpkg-query -S "$file" >/dev/null 2>&1; then
        echo "$file"
    fi
done >> "$REPORT"

###############################################################################
# Recently modified files
###############################################################################

section \
"7. RECENTLY MODIFIED SYSTEM FILES" \
"Lists regular files under common system directories modified within the last seven days."

find /etc /usr/bin /usr/sbin /bin /sbin \
    -xdev \
    -type f \
    -mtime -7 \
    -printf '%TY-%Tm-%Td %TH:%TM:%TS %u:%g %m %p\n' \
    2>/dev/null >> "$REPORT"

###############################################################################
# Persistence locations
###############################################################################

section \
"8. COMMON PERSISTENCE LOCATIONS" \
"Lists files in common service, cron, startup, and SSH persistence locations."

find \
    /etc/systemd/system \
    /etc/systemd/user \
    /etc/cron.d \
    /etc/cron.daily \
    /etc/cron.hourly \
    /etc/cron.weekly \
    /etc/cron.monthly \
    /etc/init.d \
    -type f \
    -printf '%m %u:%g %p\n' \
    2>/dev/null >> "$REPORT"

echo >> "$REPORT"
echo "User and root shell/SSH startup files:" >> "$REPORT"

find /home /root \
    -maxdepth 3 \
    -type f \
    \( \
        -name '.bashrc' \
        -o -name '.profile' \
        -o -name '.bash_profile' \
        -o -name '.zshrc' \
        -o -name 'authorized_keys' \
    \) \
    -printf '%m %u:%g %p\n' \
    2>/dev/null >> "$REPORT"

###############################################################################
# Listening services
###############################################################################

section \
"9. LISTENING NETWORK SERVICES" \
"Lists TCP and UDP sockets currently listening for connections."

if command -v ss >/dev/null 2>&1; then
    ss -lntup 2>/dev/null >> "$REPORT"
else
    echo "ss is not installed; network socket scan unavailable." >> "$REPORT"
fi

###############################################################################
# Kernel, boot, and module information
###############################################################################

section \
"10. KERNEL, BOOT, AND LOADED MODULE INFORMATION" \
"Records kernel version, boot parameters, and currently loaded kernel modules."

echo "Kernel:" >> "$REPORT"
uname -a 2>/dev/null >> "$REPORT"

echo >> "$REPORT"
echo "Kernel command line:" >> "$REPORT"
cat /proc/cmdline 2>/dev/null >> "$REPORT"

echo >> "$REPORT"
echo "Loaded kernel modules:" >> "$REPORT"
if command -v lsmod >/dev/null 2>&1; then
    lsmod 2>/dev/null >> "$REPORT"
else
    echo "lsmod is unavailable." >> "$REPORT"
fi

###############################################################################
# Troubleshooting guidance
###############################################################################

section \
"11. TROUBLESHOOTING AND INTERPRETATION" \
"General guidance for investigating findings."

cat >> "$REPORT" <<'EOF'
MODIFIED FILES
--------------
A modified file differs from the checksum recorded by the installed package.

Common legitimate causes:
  - Package updates or interrupted package transactions
  - Local administrator changes
  - Locally compiled or manually replaced binaries
  - Configuration files changed by software or automation

Suggested checks:
  - Identify the owning package with:
      dpkg-query -S /path/to/file
  - Review package history:
      grep -iE 'install|upgrade|remove' /var/log/dpkg.log
  - Reinstall the owning package only after confirming that is appropriate.
  - Compare the file against a trusted copy or the package from a trusted source.


MISSING FILES
-------------
A package expects a file that is no longer present.

Common legitimate causes:
  - Package removal or incomplete package operations
  - Manually deleted files
  - Files moved by an administrator
  - Files generated only during a particular service state

Suggested checks:
  - Check package state:
      dpkg -s package-name
  - Check pending package operations:
      dpkg --audit
  - Review:
      /var/log/dpkg.log
      /var/log/apt/history.log


SHARED MD5 HASHES
-----------------
Identical hashes are usually not suspicious. License files, documentation,
symlinks resolved to the same content, and identical package resources can
legitimately share a hash.

MD5 is useful here for detecting accidental package-file changes, but it is
not suitable as a cryptographic security guarantee against deliberate
collision attacks.


SUID, SGID, AND CAPABILITIES
----------------------------
Compare results with a known-good host or baseline. Investigate files that:
  - Are newly introduced
  - Are located in unusual writable directories
  - Have unexpected owners or permissions
  - Do not belong to an installed package


UNOWNED FILES
-------------
Unowned files can be legitimate locally compiled software, administrator
scripts, application data, or vendor software. Prioritize files in:
  - /bin
  - /sbin
  - /usr/bin
  - /usr/sbin
  - /lib
  - /lib64
  - /etc


PERSISTENCE AND NETWORK SERVICES
--------------------------------
Review unexpected:
  - systemd units
  - cron jobs
  - SSH authorized keys
  - shell startup commands
  - listening network services
  - loaded kernel modules

Correlate file modification times with authentication logs, package logs,
deployment logs, and known maintenance windows.


LIMITATIONS
-----------
This report is not a complete compromise-detection system. It may not detect:
  - Changes to files excluded from package checksum lists
  - In-memory process modification
  - Kernel-level rootkits
  - Malicious content in writable application data
  - Legitimate files altered and then restored
  - Attacks that modify or replace the local package database

For stronger assurance, keep a cryptographically protected baseline from a
known-clean system and compare future reports against it. Consider using a
dedicated host-integrity system where appropriate.
EOF

###############################################################################
# Final summary
###############################################################################

{
    echo
    echo "==============================================================================="
    echo "SUMMARY"
    echo "==============================================================================="
    echo "Modified files:              $(wc -l < "$MODIFIED" 2>/dev/null)"
    echo "Missing files:               $(wc -l < "$MISSING" 2>/dev/null)"
    echo "Unreadable/unchecked files:  $(wc -l < "$UNREADABLE" 2>/dev/null)"
    echo "Report saved to:"
    echo "  $REPORT"
    echo "==============================================================================="
} >> "$REPORT"

# Print only after all checks have completed.
print("Location of report:/home/${USER}/Desktop")

