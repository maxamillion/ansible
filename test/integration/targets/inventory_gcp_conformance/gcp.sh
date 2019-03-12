#!/usr/bin/env bash
# Wrapper to use the correct Python interpreter and support code coverage.

if [ -z "$ANSIBLE_TEST_PYTHON_INTERPRETER" ]; then
    ANSIBLE_TEST_PYTHON_INTERPRETER=$(which python)
fi

if [ -f ../../../../contrib/inventory/gce.py ]; then
    ABS_SCRIPT="../../../../contrib/inventory/gce.py"
    ABS_SCRIPT=$($ANSIBLE_TEST_PYTHON_INTERPRETER -c "import os; print(os.path.abspath('${ABS_SCRIPT}'))")
elif [ -f ~/ansible/contrib/inventory/gce.py ]; then
    ABS_SCRIPT=~/ansible/contrib/inventory/gce.py
else
    echo "Could not find gce.py!"
    exit 1
fi

TARGET=$(pwd)
# set the output dir
#echo "OUTPUT_DIR: $OUTPUT_DIR"
if [ -z ${OUTPUT_DIR+null} ]; then
    export OUTPUT_DIR=$(pwd)
fi
cd ${OUTPUT_DIR}
cp $ABS_SCRIPT .

CMD="$ANSIBLE_TEST_PYTHON_INTERPRETER gce.py"
#echo "$CMD"
exec $CMD
RC=$?
cd -
exit $RC
