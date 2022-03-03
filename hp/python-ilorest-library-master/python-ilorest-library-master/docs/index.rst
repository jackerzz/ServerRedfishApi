.. iLO RESTful API documentation master file, created by
   sphinx-quickstart on Fri Mar 11 11:34:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.
   
.. image:: /images/hpe_logo2.png
   :width: 150pt
   
|
|

Python iLO Redfish Library
==========================

The iLO Redfish Library is a python library built for interacting with systems that implement the **Redfish API**, which includes the HPE iLO RESTful API.
The library is the platform on which the `RESTful Interface tool <https://github.hpe.com/intelligent-provisioning/python-restful-interface-tool>`_ was built on.

The library can connect **remotely** to any BMC that implements a Redfish API via HTTPS or **locally** to an HPE server using the HPE CHIF interface and implements Redfish or Legacy Rest APIs.
On top of this functionality, the library also offers remote and local support for the Legacy HPE iLO RESTful API that was the starting point for the DMTF Redfish standard.

For more information on the HPE iLO RESTful API and Redfish see the `API overview <API-Overview.html>`_.

.. note::  HPE's Legacy Rest API is available starting in **iLO 4 2.00**. iLO 4 is Redfish conformant starting with **iLO 4 2.30**. In iLO 5 and above the iLO RESTful API is Redfish only.

Documentation
-------------

.. toctree::
   :maxdepth: 1
   
   API-Overview
   Installation-Guide
   Client-Quick-Start
   Advanced-Usage
   Monolith
   System-Compatibility
   Examples
   Frequently-Asked-Questions
   Reference

Get in touch with the team
--------------------------

If you have further questions, please contact the team:

* `Matthew Kocurek <https://github.com/Yergidy>`_
* `Tony Wang <https://github.com/injan0913>`_
* `Grant O'Connor <https://github.com/KeepSummerSaf3>`_
* `Matthew Whiteside <https://github.com/mwside>`_

Contributors
-------------

Contributors are listed `here <https://github.hpe.com/intelligent-provisioning/python-redfish-library/graphs/contributors>`_.

