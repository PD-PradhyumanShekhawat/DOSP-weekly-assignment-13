ERLC ?= erlc
ERL ?= erl

.PHONY: all compile test clean

all: test

compile:
	mkdir -p ebin
	$(ERLC) -o ebin src/hmac_api_auth.erl

test: compile
	$(ERLC) -o ebin test/test_hmac_api_auth.erl
	$(ERL) -noshell -pa ebin -s test_hmac_api_auth run -s init stop

clean:
	rm -rf ebin erl_crash.dump
