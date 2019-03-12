#!/usr/bin/env bash

set -eux

# set the output dir
if [ -z ${OUTPUT_DIR+null} ]; then
    export OUTPUT_DIR=$(pwd)
fi

#################################################
#   RUN THE SCRIPT
#################################################

# run the script first
export GCE_INI_PATH=gce.ini
export GCE_ZONE="us-east1-d"

# FIXME
cat << EOF > $OUTPUT_DIR/gce.ini
[gce]
EOF

rm -f script.out
./gce.py.sh | tee -a $OUTPUT_DIR/script.out
RC=$?
if [[ $RC != 0 ]]; then
    exit $RC
fi
#rm -f $OUTPUT_DIR/ec2.ini
#rm -f $OUTPUT_DIR/ec2.py
rm -rf .cache

#exit 0

#################################################
#   RUN THE PLUGIN
#################################################

# run the plugin second
#FIXME
cat << EOF > $OUTPUT_DIR/test.gcp.yml

EOF

# override boto's import path(s)
echo "PWD: $(pwd)"
export PYTHONPATH=$(pwd)/lib:$PYTHONPATH

rm -f $OUTPUT_DIR/plugin.out
ANSIBLE_JINJA2_NATIVE=1 ansible-inventory -vvvv -i $OUTPUT_DIR/test.gcp.yml --list --output=$OUTPUT_DIR/plugin.out

#################################################
#   DIFF THE RESULTS
#################################################

./inventory_diff.py $OUTPUT_DIR/script.out $OUTPUT_DIR/plugin.out
