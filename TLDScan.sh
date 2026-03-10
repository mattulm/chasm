#!/bin/sh
## Tool        :: dig (Custom Wrapper)
## Description :: Audit MX, NS, DMARC, and SOA records for domains
## Project     :: CHASM (CHeap Attack Surface Management)

## Global Variables
d=$(date +"%Y%m%d")
t=$(date +"%H%M")
domains=$1
s=$2
##############################
##############################
## SOA RECORD AUDIT
echo "Auditing the SOA (Start of Authority) records";
echo "domain, ttl, class, record_type, primary_ns, admin_email, serial" >> dig.soa.$d.$t.$s.csv
for i in $(shuf $domains ); do
   echo "Checking SOA for :: " $i;
   dig -4 -t SOA $i | grep "ER S" -A3 | grep -v ";" | awk '{ print $1, $2, $3, $4, $5, $6, $7 }' | sed 's/ /, /g' | tr [:upper:] [:lower:] >> dig.soa.$d.$t.$s.csv
done
sed -i '/, , , , , , /d' dig.soa.$d.$t.$s.csv
mv dig.soa.$d.$t.$s.csv /asm/output/dig/
##############################
## MX RECORD AUDIT
echo "I am now switching to the MX record of things with DIG";
echo "domain, ttl, class, record_type, mail_server, priority " >> dig.mx.$d.$t.$s.csv
for i in $(shuf $domains ); do
   echo "Checking the MX on" $i;
   dig -4 -t MX $i | grep "ER S" -A3 | grep -v ";" | awk '{ print $1, $2, $3, $4, $6, $5 }' | sed 's/ /, /g' | tr [:upper:] [:lower:] >> dig.mx.$d.$t.$s.csv
done
sed -i '/, , , , , /d' dig.mx.$d.$t.$s.csv
mv dig.mx.$d.$t.$s.csv /asm/output/dig/

##############################
## NS RECORD AUDIT
echo "I am now switching to the NS record of things with DIG";
echo "domain, dns_ttl, class, record_type, ns_server" >> dig.ns.$d.$t.$s.csv
for i in $(shuf $domains ); do
   echo "Checking the Name Server for :: " $i;
   dig -4 -t NS $i | grep "ER S" -A3 | grep -v ";" | awk '{ print $1, $2, $3, $4, $5 }' | sed 's/ /, /g' | tr [:upper:] [:lower:] >> dig.ns.$d.$t.$s.csv
done
sed -i '/, , , , /d' dig.ns.$d.$t.$s.csv
mv dig.ns.$d.$t.$s.csv /asm/output/dig/

##############################
## DMARC RECORD AUDIT
echo "I am now going to attempt some dmarc checks";
echo "domain, ttl, class, record_type, dmarc_ver, Purpose, fo, rua, ruf" >> dig.dmarc.$d.$t.$s.csv
for i in $(shuf $domains ); do
   echo "Checking TXT record for :: " $i;
   dig -4 -t TXT _dmarc.$i | grep "ER S" -A3 | grep "IN" | awk '{ print $1, $2, $3, $4, $5, $6, $7, $8, $9 }' | sed 's/;/ /g' | sed 's/\"//g' | sed 's/ /, /g' | sed 's/, , /, /g' | tr [:upper:] [:lower:] >> dig.dmarc.$d.$t.$s.csv
done
mv dig.dmarc.$d.$t.$s.csv /asm/output/dig/

##############################


echo "CHASM TLD Audit Complete.";
## EOF
