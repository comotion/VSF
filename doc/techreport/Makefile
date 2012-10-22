all: vsf-techreport.pdf

STYLEPATH=style

vsf-techreport.pdf: vsf-techreport.rst
	rst2pdf -c --stylesheet-path=${STYLEPATH} -s rpl.style $< -o $@


clean:
	@rm -f vsf-techreport.pdf


