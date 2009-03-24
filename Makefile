#
# Exposition PHP Libraries Makefile
#
# Targets:
#  - all: export the files from Git, produce a ZIP and a TAR archive.
#  - export: export the files from Git.
#  - zip: produce a ZIP archive.
#  - tar: produce a TAR archive.
#  - clean: remove the staged files.
#

GIT = git
ZIP = zip
TAR = tar

BUILD = ./build

NAME = openid
VERSION = latest
STAGE = $(BUILD)/$(NAME)
ARCHIVE_NAME = dokuwiki-openid-plugin
ZIP_NAME = $(ARCHIVE_NAME)-$(VERSION).zip
TAR_NAME = $(ARCHIVE_NAME)-$(VERSION).tar.gz

all: export zip tar
	@echo "Build complete."

export:
	@echo "Exporting files from Git..."
	@mkdir -p $(BUILD)
	@if [ -d "$(STAGE)" ] ; then \
		echo "Export directory already exists." ; \
	else \
		$(GIT) checkout-index -a -f --prefix=$(STAGE)/ ; \
		rm -f $(STAGE)/Makefile ; \
	fi
	@echo "Git export complete."

zip:
	@echo "Creating the ZIP archive..."
	@(cd $(BUILD) && $(ZIP) -rq $(ZIP_NAME) $(NAME))
	@echo "ZIP archive done."

tar:
	@echo "Creating the TAR archive..."
	@(cd $(BUILD) && $(TAR) -czf $(TAR_NAME) $(NAME))
	@echo "TAR archive done."

clean:
	@echo "Cleaning the build directory..."
	-@rm -rf $(STAGE)
	-@rm -f $(BUILD)/$(NAME)*.zip
	-@rm -f $(BUILD)/$(NAME)*.tar.gz
	@echo "Staged files and archives removed."
