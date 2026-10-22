cd /mnt/c/Users/matwx/Desktop/Work/matchelminski.com/CyberSecurityProjects/WebCrawler
xvfb-run -a /tmp/pwenv/bin/python -W ignore -m unittest tests.test_render 2>&1 | tail -25 | cut -c1-220
