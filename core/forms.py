#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

def testFormx1(): # an example xsrfprobe-test-form to make sure the stuff works properly ;)

    test_form_0x01 = """<form action="/somendpoint" method="post" id="xsrfprobe-xsrfprobe-test-form">
    <div><div class="xsrfprobe-test-form-item" id="edit-name-wrapper">
     <label for="edit-name">Username: <span class="xsrfprobe-test-form-required" title="This field is required.">*</span></label>
     <input type="text" maxlength="60" name="name" id="edit-name" size="15" value="test1" class="xsrfprobe-test-form-text required" />
    </div>
    <div class="xsrfprobe-test-form-item" id="edit-pass-wrapper">
     <label for="edit-pass">Password: <span class="xsrfprobe-test-form-required" title="This field is required.">*</span></label>
     <input type="password" value="a9z8e7" name="pass" id="edit-pass"  maxlength="60"  class="xsrfprobe-test-form-text required" />
    </div>
    <input type="submit" name="op" id="edit-submit" value="Log in"  class="xsrfprobe-test-form-submit" />
    <div class="item-list"><ul><li class="first"><a href="/somednpoint/register" title="Create a new user account.">Create new account</a></li>
    <li class="last"><a href="/somendpoint/tho" title="Request new password via e-mail.">Request new password</a></li>
    </ul></div><input type="hidden" name="xsrfprobe-test-form_build_id" id="xsrfprobe-test-form-6ab908" value="xsrfprobe-test-form-6a060cc6cb908"  />
    <input type="hidden" name="xsrfprobe-test-form_id" id="edit-xsrfprobe-block" value="user_login_block"  />
    </div></form> """

    return test_form_0x01

def testFormx2(): # an example of a xsrfprobe-test-form (used drupal)

    test_form_0x02 = """<form action="/somendpoint" method="post" id="xsrfprobe-xsrfprobe-test-form">
    <div><div class="xsrfprobe-test-form-item" id="edit-name-wrapper">
     <label for="edit-name">Username: <span class="xsrfprobe-test-form-required" title="This field is required.">*</span></label>
     <input type="text" maxlength="60" name="name" id="edit-name" size="15" value="test2" class="xsrfprobe-test-form-text required" />
    </div>
    <div class="xsrfprobe-test-form-item" id="edit-pass-wrapper">
     <label for="edit-pass">Password: <span class="xsrfprobe-test-form-required" title="This field is required.">*</span></label>
     <input type="password" value="a9z8e7" name="pass" id="edit-pass"  maxlength="60"  size="15"  class="xsrfprobe-test-form-text required" />
    </div>
    <input type="submit" name="op" id="edit-submit" value="Log in"  class="xsrfprobe-test-form-submit" />
    <div class="item-list"><ul><li class="first"><a href="/somednpoint/register" title="Create a new user account.">Create new account</a></li>
    <li class="last"><a href="/somendpoint/tho" title="Request new password via e-mail.">Request new password</a></li>
    </ul></div><input type="hidden" name="xsrfprobe-test-form_build_id" id="xsrfprobe-test-form-6a060cc6cb908" value="xsrfprobe-test-form-6a060cc6cb908"  />
    <input type="hidden" name="xsrfprobe-test-form_id" id="edit-xsrfprobe-block" value="user_login_block"  />
    </div></form> """

    return test_form_0x02
