#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

def form10(): # an example form to make sure the stuff works properly ;)

    form0x01 = """<form action="/drupal/?q=node&amp;destination=node"  accept-charset="UTF-8" method="post" id="user-login-form">
    <div><div class="form-item" id="edit-name-wrapper">
     <label for="edit-name">Username: <span class="form-required" title="This field is required.">*</span></label>
     <input type="text" maxlength="60" name="name" id="edit-name" size="15" value="test1" class="form-text required" />
    </div>
    <div class="form-item" id="edit-pass-wrapper">
     <label for="edit-pass">Password: <span class="form-required" title="This field is required.">*</span></label>
     <input type="password" value="a9z8e7" name="pass" id="edit-pass"  maxlength="60"  size="15"  class="form-text required" />
    </div>
    <input type="submit" name="op" id="edit-submit" value="Log in"  class="form-submit" />
    <div class="item-list"><ul><li class="first"><a href="/drupal/?q=user/register" title="Create a new user account.">Create new account</a></li>
    <li class="last"><a href="/drupal/?q=user/password" title="Request new password via e-mail.">Request new password</a></li>
    </ul></div><input type="hidden" name="form_build_id" id="form-6a060c0861888b7321fab4f5ac6cb908" value="form-6a060c0861888b7321fab4f5ac6cb908"  />
    <input type="hidden" name="form_id" id="edit-user-login-block" value="user_login_block"  />
    </div></form> """

    return form0x01
