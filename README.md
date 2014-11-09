MyPA is a self-service front end for FreeIPA.

MyPA allows users to request and recover their own user accounts without intervention from an IPA server admin.

IMPORTANT NOTE: Because users can request their own account creation, it is CRITICAL that these newly-created accounts should not have any permissions to log into secure systems.  That means that access to those systems should be controlled with HBAC rules (or similar) that do not permit new users to authenticate (e.g. the IPA default "allow_all" HBAC rule should be disabled or deleted).

MyPA is licenced under the GPLv2.
