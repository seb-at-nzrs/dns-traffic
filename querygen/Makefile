# MX
HIT_RATIO=0.45
EDNS_RATIO=0.80
DO_BIT_RATIO=0.79
RECURS_RATIO=0.65
EDNS_BUF_FILE=edns-buffer-size.example.dat
QTYPE_DISTRIB_FILE=qtype.example.dat
# NORMAL
#HIT_RATIO=0.92
#EDNS_RATIO=0.56
#DO_BIT_RATIO=0.5254
#RECURS_RATIO=0.0735
#EDNS_BUF_FILE=edns-buffer-size-normal.dat
#QTYPE_DISTRIB_FILE=qtype-normal.dat
###
NUM_QUERIES=1000
HIT_NAMES_FILE=
MISS_NAMES_FILE=
MISS_GEN=./miss-name-generator.rb
GEN_OPTS=--num-queries=${NUM_QUERIES} --edns-ratio=${EDNS_RATIO} \
        --do-bit-ratio=${DO_BIT_RATIO} --recursive-ratio=${RECURS_RATIO} \
        --hit-ratio=${HIT_RATIO} \
        --edns-buffer-size-file=${EDNS_BUF_FILE} \
        --qtype-distrib-file=${QTYPE_DISTRIB_FILE} \
        --hit-names-file=hit-names.txt \
        --miss-names-file=miss-names.txt
GEN_DEPS= ${EDNS_BUF_FILE} \
          ${QTYPE_DISTRIB_FILE} \
          hit-names.txt \
          miss-names.txt

all: query-list.dat

parser: parse-json-input.c
	gcc -g -o $@ $< -ljansson

miss-names.txt: ${MISS_GEN} sld-distrib.txt
	ruby ${MISS_GEN} -e hit-names.txt -n 20000 > $@

hit-names.txt: ${ZONEFILE}
	awk '{print $$1}' ${ZONEFILE} | uniq > $@

query-list.dat: querygen.rb ${GEN_DEPS}
	./querygen.rb ${GEN_OPTS} > $@

ql.dat: querygen.rb ${GEN_DEPS}
	./querygen.rb ${GEN_OPTS} > $@
