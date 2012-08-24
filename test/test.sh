#!/bin/bash

self=`pwd`/$0
case_dir=`dirname $self`/case

fail()
{
	echo Fail
	exit 1
}

for dir in $case_dir/*; do
	[ -d $dir ] || continue
	pkt=$dir/pkt.pcap
	rule=$dir/rules.conf
	[ -f $rule ] || rule=$case_dir/rules.conf
	keyword=$dir/keywords.conf
	log=$dir/log.log
	tmp=`mktemp /tmp/snoopy.XXXXXX`
	echo -n "Testing $dir ... "
	./snoopy -r $pkt -R $rule -k $keyword -l $tmp
	[ $? -ne 0 ] && fail
	diff=`diff $log $tmp`
	[ -z "$diff" ] || fail
	echo "OK"
	rm -f $tmp
done
