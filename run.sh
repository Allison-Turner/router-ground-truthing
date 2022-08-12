#!/usr/bin/env bash

FILE_OWNER=$1

if [ -z "$FILE_OWNER" ];
then
    echo "Please include the name of the user who should own the generated network monitoring artifacts"
    echo "You can check your username with the whoami command"
    exit
fi

TS=$(date +"%Y-%m-%d-%H-%M-%S")

HELPER_LOG="./helper.log"
PCAP_DIR="./pcaps"
OUTPUT_DIR="./logs"
REPETITIONS=30
TIMEOUT=3
DUMPCAP_DUR=$(($REPETITIONS * $TIMEOUT + 3))

init(){
    if [ ! -f "$HELPER_LOG" ]; then
        touch $HELPER_LOG
        chown $FILE_OWNER $HELPER_LOG
    fi

    if [ ! -d "$PCAP_DIR" ]; then
        mkdir "$PCAP_DIR"
        chown $FILE_OWNER $PCAP_DIR
    fi

    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir "$OUTPUT_DIR"
        chown $FILE_OWNER $OUTPUT_DIR
    fi
}

start_packet_capture(){
    DURATION=$1
    FILE=$(dumpcap -i wlp2s0 --autostop duration:$DURATION -n -q 2>&1 >/dev/null | grep "File:" | awk '{print $2}')
    echo $FILE > $HELPER_LOG
}

move_pcap_to_result_dir(){
    RESULT_DIR=$1
    TIMESTAMP=$2

    ORIG_FILEPATH=$(cat $HELPER_LOG)
    ORIG_FILENAME=$(basename $ORIG_FILEPATH)
    EXTENSION=$(echo "${ORIG_FILENAME##*.}")
    MOVED_FILEPATH="$RESULT_DIR/$ORIG_FILENAME"
    NEW_FILENAME="router-discovery-$TIMESTAMP.$EXTENSION"
    NEW_FILEPATH="$RESULT_DIR/$NEW_FILENAME"

    mv $ORIG_FILEPATH $RESULT_DIR
    mv $MOVED_FILEPATH $NEW_FILEPATH
    chown $FILE_OWNER $NEW_FILEPATH
    wait
}

init
wait

# start packet capture
start_packet_capture $DUMPCAP_DUR &

# start python script
python3 router_discovery.py -t $TS -r $REPETITIONS -f $TIMEOUT -i IPv6

wait

move_pcap_to_result_dir $PCAP_DIR $TS