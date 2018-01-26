signature file-shellshock-php {
	file-mime "text/x-php", 60
	file-magic /.*<\?php/
}

signature file-shellshock-perl {
	file-mime "text/x-perl", 60
	file-magic /\x23\x21.*bin\/perl/
}

signature file-shellshock-shellscript {
	file-mime "text/x-shellscript", 60
	file-magic /\x23\x21.*bin\/.?.?sh/
}