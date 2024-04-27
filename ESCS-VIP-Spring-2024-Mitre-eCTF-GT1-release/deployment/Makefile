
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	printf '%s\n' '#define SECRET 1234' > global_secrets.h \
	'#define COMP_SECRET "0885a0cb8fa9410dd80a264417586680425e3ea71a3844120c2475bd412f6427"' > global_secrets.h \
	'#define AP_SECRET "5299fc7adf2bdffd067ed2dd565f374992ff1fca3a6cf056b62b60d284b46c22"' > global_secrets.h
clean:
	rm -f global_secrets.h
