#!/bin/bash

# Temporary files to store current and previous sizes
current_file="/tmp/current_sizes.txt"
previous_file="/tmp/previous_sizes.txt"

# Initialize previous file
du -b * > "$previous_file"  # Using -b for byte size

# Function to add color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
cyan='\033[0;36m'
nc='\033[0m' # No Color

# Clear the screen for the first display
clear

for i in $(seq 1 100000); do
    echo -e "${cyan}"
    echo -e "###############################################"
    echo -e "#                                             #"
    echo -e "#     File Size Monitor - $(date "+%Y-%m-%d %H:%M:%S")     #"
    echo -e "#                                             #"
    echo -e "###############################################"
    echo -e "${nc}"

    # Get current sizes in bytes and save to current_file
    du -b * > "$current_file"  # Using -b for byte size

    # Display the sizes and calculate differences
    echo -e "\nCurrent Sizes:\n"

    # Print headers with color
    printf "${yellow}%-40s %-15s %-20s${nc}\n" "File/Directory" "Size (bytes)" "Change (bytes)"
    printf "${yellow}%-40s %-15s %-20s${nc}\n" "-------------------" "-------------" "--------------"

    # Display sizes and calculate differences, excluding specific files
    awk -v red="$red" -v green="$green" -v nc="$nc" 'NR==FNR{a[$2]=$1; next}
    $2 != "current_sizes.txt" && $2 != "monitor_size.sh" && $2 != "previous_sizes.txt" {
        size_diff = $1 - (a[$2] ? a[$2] : 0);
        if(size_diff > 0) {
            change=sprintf("+%d", size_diff)
            color=red
        } else if(size_diff < 0) {
            change=sprintf("%d", size_diff)
            color=green
        } else {
            change="0"
            color=nc
        }
        printf "%-40s %-15s %s%-20s%s\n", $2, $1, color, change, nc
    }' "$previous_file" "$current_file" | column -t

    # Copy current sizes to previous for next iteration
    cp "$current_file" "$previous_file"

    # Countdown timer with progress bar
    total_time=60
    echo -e "\nNext update in:"
    for ((sec=total_time; sec>0; sec--)); do
        percent=$((100 - (sec * 100 / total_time)))
        bar_width=50
        filled=$(( (percent * bar_width) / 100 ))
        empty=$(( bar_width - filled ))
        # Optional: Add color to progress bar
        printf "\r["
        printf "${green}%0.s#${nc}" $(seq 1 $filled)
        printf "%0.s " $(seq 1 $empty)
        printf "] %3d%% %3d seconds remaining" "$percent" "$sec"
        sleep 1
    done
    echo ""

    # Clear the screen for the next iteration
    clear
done

# Cleanup
rm "$current_file" "$previous_file"