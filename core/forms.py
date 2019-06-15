#!/usr/bin/env python3
# coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

def testFormx1(): # an example xsrfprobe-test-form to make sure the stuff works properly ;)

    test_form_0x01 = """
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
	<p>
		<label for="user_login">Username or Email Address<br>
		<input name="log" class="input" id="user_login" type="text" size="20" value="" autocapitalize="off"></label>
	</p>
	<p>
		<label for="user_pass">Password<br>
		<input name="pwd" class="input" id="user_pass" type="password" size="20" value=""></label>
	</p>
			<p class="forgetmenot"><label for="rememberme"><input name="rememberme" id="rememberme" type="checkbox" value="forever"> Remember Me</label></p>
	<p class="submit">
		<input name="wp-submit" class="button button-primary button-large" id="wp-submit" type="submit" value="Log In">
				<input name="redirect_to" type="hidden" value="/niqqa.php">
					<input name="testcookie" type="hidden" value="1">
	</p>
	</form> """

    return test_form_0x01

def testFormx2(): # an example of a xsrfprobe-test-form (used drupal)

    test_form_0x02 = """
    <form name='shit' id="contact" action="/nibba.php" method="post">
     <h3>Colorlib Contact Form</h3>
     <h4>Contact us for custom quote</h4>
     <fieldset>
     <input placeholder="Your name" type="text" tabindex="1" required autofocus>
     </fieldset>
     <fieldset>
     <input placeholder="Your Email Address" type="email" tabindex="2" required>
     </fieldset>
     <fieldset>
     <input placeholder="Your Phone Number (optional)" type="tel" tabindex="3" required>
     </fieldset>
     <fieldset>
     <input placeholder="Your Web Site (optional)" type="url" tabindex="4" required>
     </fieldset>
     <fieldset>
     <textarea placeholder="Type your message here...." tabindex="5" required></textarea>
     </fieldset>
     <fieldset>
     <button name="submit" type="submit" id="contact-submit" data-submit="...Sending">Submit</button>
     </fieldset>
    </form> """

    return test_form_0x02
