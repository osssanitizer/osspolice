#!/bin/bash
# Define a timestamp function
timestamp() {
	date +"%m_%d_%y_%H_%M_%S"
}

delimeter=','
progressBarWidth=20

username="kkk909090"
passwd="LH2-bNY-GBg-RXL"

# Function to draw progress bar
progressBar () {
	taskCount=$1
	taskDone=$2
	text=$3

	# Calculate number of fill/empty slots in the bar
	progress=$(echo "$progressBarWidth/$taskCount*$tasksDone" | bc -l)  
	fill=$(printf "%.0f\n" $progress)
	if [ $fill -gt $progressBarWidth ]; then
	  fill=$progressBarWidth
	fi
	empty=$(($fill-$progressBarWidth))
	
	# Percentage Calculation
	percent=$(echo "100/$taskCount*$tasksDone" | bc -l)
	percent=$(printf "%0.2f\n" $percent)
	if [ $(echo "$percent>100" | bc) -gt 0 ]; then
	  percent="100.00"
	fi
	
	# Output to screen
	printf "\r["
	printf "%${fill}s" '' | tr ' ' \#
	printf "%${empty}s" '' | tr ' ' \ 
	printf "] $percent%% - $text "
}

# clone repos
clone_repo() { 
	list=$1		# list of repos
	path=$2		# clone path
	logfile=$3

	cat $list | while read line
		do
			id=$(echo $line | cut -f1 -d$delimeter)
			name=$(echo $line | cut -f2 -d$delimeter)

			# Add some friendly output
			echo -n "Clonning $name..." >> $logfile
			
			if [ ! -e $path/$id ]; then
				url="https://$username:$passwd@github.com/$name"
				git clone --depth=1 $url $path/$id &> /dev/null
				if [ $? -ne 0 ]; then
					echo "Failed" >> $logfile
				else
					echo "OK" >> $logfile
				fi
			else
				echo "Exists" >> $logfile
			fi

		done
} 

# check num of parameters
if [ $# -ne 2 ]; then
	echo "Usage: " $0 "<path to repo list> <dst dir>"
	exit
fi

# validate parameter
if [ ! -f $1 ]; then
	echo "$1 is not a file"
	echo "Usage: " $0 "<path to repo list> <dst dir>"
	exit
fi

# check for GIT installation
if [ $(which git | wc -l) -eq 0 ]; then
	echo "GIT not installed"
	exit
fi

# check for "split" installation
if [ $(which split | wc -l) -eq 0 ]; then
	echo "split tool not installed"
	exit
fi

# check for the presence of /tmp
if [ ! -e "/tmp" ]; then
	mkdir /tmp
	if [ $? -ne 0 ]; then
		echo "failed to create /tmp dir"
		exit
	fi
fi

# if $repo_list is absolute or relative
full_repo_list=$1
if [[ "$full_repo_list" != /* ]]; then
	full_repo_list=$(pwd)/$1
fi

# get dst/clone path
clone_path=$2
if [[ "$clone_path" != /* ]]; then
	clone_path=$(pwd)/$2
fi
if [ ! -e $clone_path ]; then
	mkdir $clone_path
fi
if [ ! -d $clone_path ]; then
	echo "$clone_path is not a dir"
	echo "Usage: " $0 "<path to repo list> <dst dir>"
	exit
fi

# get only c/c++ repos
header_expected_csv="gh_id,full_name,html_url,primary_language,languages"
header_expected_psv="gh_id|full_name|html_url|primary_language|languages|subscribers_count|stargazers_count|forks_count|created_at|updated_at|pushed_at|size"

header_found=$(head -n1 $full_repo_list)
if [ $header_expected_csv == $header_found ]; then
	delimeter=','
elif [ $header_expected_psv == $header_found ]; then
	delimeter='|'
else
	echo "repo file format not recognized"
	echo $header_found
	exit
fi

ts=$(timestamp)
repo_list=/tmp/rlist.$ts
repo_list_split_dir=/tmp/repo_list.$ts

# filter out c/c++ repos
cat $full_repo_list | grep "\"\"C\"\":\|\"\"C++\"\":" | cut -f1,2 -d"," > $repo_list

# check number of filtered repos
num_repos=$(wc -l $repo_list | awk '{ print $1 }')
num_cpus=$(cat /proc/cpuinfo  | grep processor | wc -l)
repos_per_cpu=$(expr $num_repos / $(expr 2 \* $num_cpus))

# split repo list
mkdir $repo_list_split_dir
cd $repo_list_split_dir
split -l $repos_per_cpu $repo_list
cd - &> /dev/null

# Ignore signals
trap '' INT
trap '' TERM

# start cloning repos
logfile=/tmp/rlist.cloned.$ts
for list in $(find /tmp/repo_list.$ts/. -type f)
	do
   		clone_repo $list $clone_path $logfile &
	done

## Collect task count
taskCount=$num_repos
tasksDone=0

while [ $tasksDone -ne $taskCount ]
	do
		# Draw the progress bar
		progressBar $taskCount $taskDone "Clonned $tasksDone/$taskCount repos"

		# Do your task
		tasksDone=$(wc -l $logfile | awk '{ print $1 }')
	done

wait
progressBar $taskCount $taskDone "Clonned $tasksDone/$taskCount repos"
echo ""

# remove residue
rm -rf $repo_list_split_dir
rm -f $repo_list $logfile
