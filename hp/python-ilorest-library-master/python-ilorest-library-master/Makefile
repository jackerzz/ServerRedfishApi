UNZIP=$(shell which unzip)
EXPORT=$(shell which export)
FIND=$(shell which find)
ECHO=$(shell which echo)
RM=$(shell which rm)
PYTHON=$(shell which python)
PYLINT=$(shell which pylint)
NOSE=$(shell which nosetests)
CREATE_CHROOT := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/create_chroot.sh
CHROOT := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/tools/muchroot
BUILD_DIR := $(shell pwd)/.blddir
SOURCEDIR := $(shell pwd)/
ZYPPER := zypper --non-interactive install
TOPDIR:=$(shell pwd)/topdir
BUILD_DIR := $(shell pwd)/.blddir
SRCROOT := $(shell pwd)
CHROOT_LOCAL_DIR:= $(shell pwd)

NAME:=ilorest
VERSION:=2.4.0
RELEASE:=1
SPHINXBUILD:=$(BUILD_DIR)/pylib/Sphinx-1.0.7/sphinx-build.py
BLOFLY := /net
#CREATE_CHROOT := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/create_chroot.sh
CREATE_CHROOT := $(CHROOT_LOCAL_DIR)/chrootbuilder/create_chroot.sh
#CHROOT := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/tools/muchroot
CHROOT := $(CHROOT_LOCAL_DIR)/chrootbuilder/tools/muchroot
UNAME_SPOOF := /net/blofly.us.rdlabs.hpecorp.net/data/blofly/iss-linux-sdk/chrootbuilder/tools/uname_spoof
export CHROOT_DESTDIR=/home

ifdef MTX_PRODUCT_VERSION
  VERSION:=$(MTX_PRODUCT_VERSION)
endif

ifdef MTX_BUILD_NUMBER
  RELEASE:=$(MTX_BUILD_NUMBER)
endif


DEBCHROOTD := $(BUILD_DIR)/chroots/squeeze

all: freeze-src rpms

rpms:
	$(call freeze-chroot,x86_64)

	#$(CHROOT) $(DEBCHROOTD) bash -c 'useradd -m monkey'
	#cp "$(NAME)-$(VERSION).tar.bz2" $(DEBCHROOTD)/home/monkey
	#$(CHROOT) $(DEBCHROOTD) bash -c 'su - monkey -c "mkdir -p ~/build && cd ~/build && mkdir -p BUILD RPMS SOURCES SPECS SRPMS"'
	#echo "export LDFLAGS=-L/usr/local/ssl/lib/" > $(DEBCHROOTD)/home/monkey/c.sh
	#echo "export SL_INSTALL_PATH=/usr/local/ssl" >> $(DEBCHROOTD)/home/monkey/c.sh
	#echo "export OPENSSL_FIPS=1" >> $(DEBCHROOTD)/home/monkey/c.sh
	#echo "export LD_LIBRARY_PATH=/usr/local/ssl/lib/" >> $(DEBCHROOTD)/home/monkey/c.sh
	#echo "export CPPFLAGS=-I/usr/local/ssl/include/ -I/usr/local/ssl/include/openssl/" >> $(DEBCHROOTD)/home/monkey/c.sh
	#echo "rpmbuild -ta --define '_topdir /home/monkey/build/' /home/monkey/$(NAME)-$(VERSION).tar.bz2 " >> $(DEBCHROOTD)/home/monkey/c.sh
	#$(CHROOT) $(DEBCHROOTD) bash -c 'chmod a+x /home/monkey/c.sh'
	#$(CHROOT) $(DEBCHROOTD) bash -c 'su - monkey -c "/home/monkey/c.sh"'
	#cp -r $(DEBCHROOTD)/home/monkey/build/RPMS/ .

	#-find ./RPMS -type f -name '*-debuginfo-*.rpm' -exec rm -f {} \;
	#-find ./RPMS -type d -empty -exec rmdir {} \;

ifdef MTX_COLLECTION_PATH
	#cp -r ./RPMS $(MTX_COLLECTION_PATH)/
	# hpsign will error out if signing not successful
	hpsign --signonly `find /opt/mxdk/buildagent/work/MTX_COLLECTION_PATH -type f -name '*.rpm'`
endif

freeze-src:
	rm -rf hp
	git clone git@github.hpe.com:ess-morpheus/chrootbuilder.git $(CHROOT_LOCAL_DIR)/chrootbuilder

define freeze-chroot
	rm -rf $(BUILD_DIR)/chroots
	# create the chroot

	$(CREATE_CHROOT) -d SLES12SP2 -a $1 -D $(DEBCHROOTD)

	#import keys
	cp -r $(CHROOT_LOCAL_DIR)/chrootbuilder/public_keys $(DEBCHROOTD)/
	$(CHROOT) $(DEBCHROOTD) mkdir -p /usr/lib/rpm/gnupg/
	#$(CHROOT) $(DEBCHROOTD) bash -c 'gpg --import /public_keys/*.asc'

	$(CHROOT) $(DEBCHROOTD) zypper --non-interactive install zlib-devel libffi-devel openssl
	$(CHROOT) $(DEBCHROOTD) zypper --non-interactive install libxml2-devel libxslt-devel ncurses-devel expat sqlite3-devel readline-devel bzip2
	$(CHROOT) $(DEBCHROOTD) openssl version
	$(CHROOT) $(DEBCHROOTD) bash -c 'export LC_ALL=en_US.UTF-8'
	$(CHROOT) $(DEBCHROOTD) bash -c 'export PYTHONIOENCODING=UTF-8'

	#tar -xvf $(SRCROOT)/packaging/python3/openssl-1.0.2u.tar.gz -C $(DEBCHROOTD)
	#tar -xvf $(SRCROOT)/packaging/python3/openssl-fips-2.0.16.tar.gz -C $(DEBCHROOTD)

	#$(CHROOT) $(DEBCHROOTD) bash -c 'cd /openssl-fips-2.0.16 && ./config && make && make install && cd ..'
	#$(CHROOT) $(DEBCHROOTD) bash -c 'cd /openssl-1.0.2u && ./config fips shared --with-fipsdir=/usr/local/ssl/fips-2.0 -m64 -Wa,--noexecstack threads no-idea no-mdc2 no-rc5 no-krb5 no-ssl2 no-ssl3 enable-asm enable-camellia enable-seed enable-tlsext enable-rfc3779 enable-cms && make depend && make install'
	#$(CHROOT) $(DEBCHROOTD) /usr/local/ssl/bin/./openssl version

	#$(CHROOT) $(DEBCHROOTD) ln -s -f /usr/local/ssl/bin/openssl /usr/bin/openssl
	#$(CHROOT) $(DEBCHROOTD) openssl version

	#$(CHROOT) $(DEBCHROOTD) mv /usr/lib64/libcrypto.so.1.1 /usr/lib64/old_libcrypto.so.1.1
	#$(CHROOT) $(DEBCHROOTD) mv /usr/lib64/libssl.so.1.1 /usr/lib64/old_libssl.so.1.1

	#$(CHROOT) $(DEBCHROOTD) cp /usr/local/ssl/lib/libcrypto.so.1.0.0 /usr/lib64/ && \
	#$(CHROOT) $(DEBCHROOTD) cp /usr/local/ssl/lib/libssl.so.1.0.0 /usr/lib64/

	tar xf $(SRCROOT)/packaging/python3/Python-3.7.3.tgz -C $(DEBCHROOTD)

	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /Python-3.7.3 && ./configure --prefix=/usr/local/python3.7 --enable-shared --with-openssl=/usr/local/ssl/'

	$(CHROOT) $(DEBCHROOTD) make -C /Python-3.7.3
	$(CHROOT) $(DEBCHROOTD) make -C /Python-3.7.3 install

	$(CHROOT) $(DEBCHROOTD) cp /usr/local/python3.7/lib/libpython3.7m.so.1.0 /usr/lib64/
	$(CHROOT) $(DEBCHROOTD) cp /usr/local/python3.7/lib/libpython3.7m.so.1.0 /lib64/

	#Added external packages
	$(CHROOT) $(DEBCHROOTD) bash -c '/usr/local/python3.7/bin/python3.7 -m ensurepip --upgrade'
	mkdir -p $(DEBCHROOTD)/collection/
	$(CHROOT) $(DEBCHROOTD) bash -c 'update-alternatives --install /usr/bin/python3 python3 /usr/local/python3.7/bin/python3.7 1 && update-alternatives --config python3 && python3 --version'

	unzip $(SRCROOT)/packaging/ext/setuptools-50.3.2.zip -d $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /setuptools-50.3.2 && /usr/local/python3.7/bin/python3.7 setup.py install'
	tar xfz $(SRCROOT)/packaging/ext/pyinstaller-hooks-contrib-2020.10.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /pyinstaller-hooks-contrib-2020.10 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/python-dotenv-0.15.0.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /python-dotenv-0.15.0 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/altgraph-0.17.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /altgraph-0.17 && /usr/local/python3.7/bin/python3.7 setup.py install'

	#tar xfz $(SRCROOT)/packaging/pyinstaller/PyInstaller-3.6.tar.gz -C $(DEBCHROOTD)
	#$(CHROOT) $(DEBCHROOTD) bash -c 'cd /PyInstaller-3.6 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/jsonpointer-2.0.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /jsonpointer-2.0 && alias python3=/usr/local/python3.7/bin/python3.7 && python3 setup.py install && python3 setup.py bdist_rpm --dist-dir /collection/'

	tar xfz $(SRCROOT)/packaging/ext/six-1.15.0.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /six-1.15.0 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/ply-3.11.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /ply-3.11 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/decorator-4.4.2.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /decorator-4.4.2 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/jsonpatch-1.26.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /jsonpatch-1.26 && alias python3=/usr/local/python3.7/bin/python3.7 && python3 setup.py install && python3 setup.py bdist_rpm --dist-dir /collection/'

	tar xfz $(SRCROOT)/packaging/ext/jsonpath-rw-1.4.0.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /jsonpath-rw-1.4.0 && alias python3=/usr/local/python3.7/bin/python3.7 && python3 setup.py install && python3 setup.py bdist_rpm --dist-dir /collection/'

	tar xfz $(SRCROOT)/packaging/ext/setproctitle-1.1.10.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /setproctitle-1.1.10 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/pyudev-0.22.0.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /pyudev-0.22.0 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/jsondiff-1.2.0.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /jsondiff-1.2.0 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/pyaes-1.6.1.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /pyaes-1.6.1 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/urllib3-1.26.2.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /urllib3-1.26.2 && alias python3=/usr/local/python3.7/bin/python3.7 && python3 setup.py install && python3 setup.py bdist_rpm --dist-dir /collection/'

	tar xfz $(SRCROOT)/packaging/ext/colorama-0.4.4.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'export LC_ALL=en_US.UTF-8 && cd /colorama-0.4.4 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/tabulate-0.8.7.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /tabulate-0.8.7 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/wcwidth-0.2.5.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /wcwidth-0.2.5 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/prompt_toolkit-3.0.8.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /prompt_toolkit-3.0.8 && /usr/local/python3.7/bin/python3.7 setup.py install'

	tar xfz $(SRCROOT)/packaging/ext/certifi-2020.11.8.tar.gz -C $(DEBCHROOTD)
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /certifi-2020.11.8 && /usr/local/python3.7/bin/python3.7 setup.py install'

	#cp -r $(MTX_STAGING_PATH)/externals/*.zip packaging/ext
	#cp -r $(SRCROOT)/*.* $(DEBCHROOTD)/buildpwd
	#$(CHROOT) $(DEBCHROOTD) bash -c 'cd /'
	#unzip packaging/ext/python-ilorest-library-$(MX_ILOREST_LIB_VERSION).zip -d $(DEBCHROOTD)

	mkdir -p $(DEBCHROOTD)/buildpwd/
	cp -r $(SRCROOT)/* $(DEBCHROOTD)/buildpwd
	$(CHROOT) $(DEBCHROOTD) bash -c 'update-alternatives --install /usr/bin/python3 python3 /usr/local/python3.7/bin/python3.7 1 && update-alternatives --config python3 && python3 --version && \
	alias python3=/usr/local/python3.7/bin/python3.7 && cd /buildpwd/ && python3 setup.py bdist_rpm --dist-dir /collection/'
	mv $(DEBCHROOTD)/collection/*.noarch.rpm ${MTX_COLLECTION_PATH}/
endef

bdist-rpm:
	zypper --non-interactive install rpm-build
	$(eval DIR=$(shell pwd))
	$(eval ILOREST=$(DIR)/ilorest/src)
	$(eval PYTHONPATH=$(ILOREST):$(PYTHONPATH))
	mkdir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/setuptools-2.2.tar.gz
	cd ./setuptools-2.2 && \
	$(PYTHON) setup.py install
	tar xfz ./packaging/ext/PySocks-1.6.8.tar.gz
	cd ./PySocks-1.6.8 && \
	$(PYTHON) setup.py install
	tar xfz ./packaging/ext/wheel-0.36.1.tar.gz
	cd ./wheel-0.36.1 && \
	$(PYTHON) setup.py install
	unzip ./packaging/ext/recordtype-1.1.zip
	cd ./recordtype-1.1 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/pypandoc-1.4.tar.gz
	cd ./pypandoc-1.4 && \
	$(PYTHON) setup.py install
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/jsonpointer-1.10.tar.gz
	cd ./jsonpointer-1.10 && \
	iconv -f 'UTF-8' -t 'ASCII//TRANSLIT//IGNORE' jsonpointer.py > jp && \
	cp -f jp jsonpointer.py
	cd ./jsonpointer-1.10 && \
	rm jp
	cd ./jsonpointer-1.10 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/jsonpatch-1.16.tar.gz
	cd ./jsonpatch-1.16 && \
	iconv -f 'UTF-8' -t 'ASCII//TRANSLIT//IGNORE' jsonpatch.py > jp && \
	cp -f jp jsonpatch.py
	cd ./jsonpatch-1.16 && \
	rm jp
	cd ./jsonpatch-1.16 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/jsonpath-rw-1.4.0.tar.gz
	cd ./jsonpath-rw-1.4.0 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/decorator-4.1.2.tar.gz
	cd ./decorator-4.1.2 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/six-1.10.0.tar.gz
	cd ./six-1.10.0 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/urllib3-1.23.tar.gz
	cd ./urllib3-1.23 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	tar xfz ./packaging/ext/ply-3.10.tar.gz
	cd ./ply-3.10 && \
	$(PYTHON) setup.py bdist_rpm --dist-dir ${MTX_COLLECTION_PATH}/python2/
	rm -rf ${MTX_COLLECTION_PATH}/*.src.rpm
	rm -rf ${MTX_COLLECTION_PATH}/python2/*.src.rpm


define build-pkg
	tar xfz $(DEBCHROOTD)/buildpwd/packaging/ext/$1* -C $(BUILD_DIR)/buildpwd/
	$(CHROOT) $(DEBCHROOTD) bash -c 'cd /buildpwd/$1 && python3 setup.py bdist_rpm --dist-dir /collection/'
	rm -r $(BUILD_DIR)/buildpwd/$1
endef

#export LC_ALL=en_US.UTF-8
#export PYTHONIOENCODING=utf-8
bdist-rpm-python3:
	$(CREATE_CHROOT) -d SLES12SP2 -D $(BUILD_DIR)
	$(CHROOT) $(BUILD_DIR) $(ZYPPER) python3 python3-setuptools
	mkdir -p $(BUILD_DIR)/buildpwd $(BUILD_DIR)/collection/
	cp -a $(SOURCEDIR)* $(BUILD_DIR)/buildpwd

	$(call build-pkg,recordtype-1.3)
	$(call build-pkg,pypandoc-1.4)
	$(call build-pkg,jsonpointer-2.0)
	$(call build-pkg,jsonpatch-1.26)
	$(call build-pkg,jsonpath-rw-1.4.0)
	#$(call build-pkg,decorator-4.1.2)
	$(call build-pkg,urllib3-1.26.2)
	$(call build-pkg,ply-3.11)
	$(call build-pkg,six-1.15.0)
	#cd $(BUILD_DIR)/collection/ && rename "" python3- *.rpm
	$(CHROOT) $(BUILD_DIR) bash -c 'cd /buildpwd/ && python3 setup.py bdist_rpm --dist-dir /collection/'
	#cd $(BUILD_DIR)/collection/ && rename python- python3- *.rpm
	mkdir ${MTX_COLLECTION_PATH}/python3/
	mv $(BUILD_DIR)/collection/*.noarch.rpm ${MTX_COLLECTION_PATH}/python3/
	rm -rf ${MTX_COLLECTION_PATH}/*.src.rpm
	rm -rf ${MTX_COLLECTION_PATH}python3/*.src.rpm
