#!/bin/bash

set -e

local_path=$(cd "$(dirname "$0")"; pwd)
root_dir=$(cd $local_path/../../../../..; pwd)

param_path=$root_dir/build/script
param_json=$root_dir/build/config/target_config/ws53/param_sector/param_sector.json
params_bin_path=$root_dir/interim_binary/ws53/bin/boot_bin/partition.bin
rm -f $params_bin_path
python3 $param_path/param_packet.py $param_json $params_bin_path
