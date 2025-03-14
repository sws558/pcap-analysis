.PHONY: clean help run install
help:
	@echo "Usage: make [target]"
	@echo "Available targets:"
	@echo "  clean:		remove all generated files"
	@echo "  help:		show this help"
	@echo "  run:		run the program"
	@echo "  install:		install the program"
clean:
	- @rm ./store/pcap/*
	- @rm ./store/files/All/*
	- @rm ./store/files/FTP/*
	- @rm ./store/files/Mail/*
	- @rm ./store/files/pdf/*
	- @rm ./store/files/Web/*
	- @rm ./store/files/csv/*
run:
	@python run.py
install:
	@python run.py