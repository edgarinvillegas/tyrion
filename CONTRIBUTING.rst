============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every
little bit helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------

Report Bugs
~~~~~~~~~~~

Report bugs at https://github.com/edgarinvillegas/tyrion/issues.

If you are reporting a bug, please include:

* Your operating system name and version (if relevant).
* Any details about your local setup that might be helpful in troubleshooting.
* If you can, provide detailed steps to reproduce the bug.
* If you don't have steps to reproduce the bug, just note your observations in
  as much detail as you can. Questions to start a discussion about the issue
  are welcome.

Fix Bugs
~~~~~~~~

Look through the GitHub issues for bugs. Anything tagged with "bug"
is open to whoever wants to implement it.

Implement Features
~~~~~~~~~~~~~~~~~~

Look through the GitHub issues for features. Anything tagged with "enhancement"
is open to whoever wants to implement it.


Write Documentation
~~~~~~~~~~~~~~~~~~~

Snappass could always use better documentation, whether as part of the
official docs, in docstrings, or even on the web in blog posts, articles, and
such.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file an issue at
https://github.com/edgarinvillegas/tyrion/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Note that this project has an intentionally narrow scope.
  Our target users are small organizations that really need a
  quick and dirty way to exchange secrets.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)


Setting Up the Code for Local Development
-----------------------------------------

Here's how to set up ``snappass`` for local development.

1. Fork the ``snappass`` repo on GitHub.
2. Clone your fork locally::

    $ git clone git@github.com:your_name_here/snappass.git

3. Install your local copy into a ``virtualenv``. Assuming you have
   ``virtualenvwrapper`` installed, this is how you set up your fork for local
   development::

    $ mkvirtualenv snappass
    $ cd snappass/
    $ python setup.py develop
    $ pip install -r dev-requirements.txt

4. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

5. You can test your changes in a development server with debug and autoreload::

    $ docker run -d --name redis-server -p 6379:6379 redis
    $ export FLASK_DEBUG=1 && \
      export FLASK_APP=snappass.main && \
      export NO_SSL=True
    $ flask run

  You now have a running instance on localhost:5002/

6. When you're done making changes, check that your changes pass the tests and
   flake8::

    $ flake8 snappass tests.py setup.py
    $ tox

7. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

8. Check that the test coverage hasn't dropped::

    $ coverage run --source snappass tests.py
    $ coverage report -m
    $ coverage html

9. Submit a pull request through the GitHub website.

Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.rst.
3. The pull request should work for Python 2.6, 2.7 and 3.3+. Check
   `Travis`_ and make sure that
   the tests pass for all supported Python versions.

.. _Travis: https://travis-ci.org/pinterest/snappass/pull_requests
