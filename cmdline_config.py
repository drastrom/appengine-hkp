import sys, os
# Add any libraries installed in the "lib" folder.
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lib'))
# Add python-pgpdump git submodule
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lib', 'python-pgpdump'))
# Add py2casefold git submodule
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lib', 'py2casefold'))
