# OSU CS 493 Portfolio Assignment
A simple Python Flask REST API for CS 493 Cloud Application Development, based on Google App Engine platform and Google Datastore. 

Users are authorized via Auth0 provided jwt. Authorized Users may perform CRUD operations may perform operations on Boat entities. Unauthorized users may perform CRUD operations on Slip entities without boats. Authorized users may perform CRUD operations on Slips with Boats. Boats may be docked at Slips in a 1 to 1 optional relationship. 

