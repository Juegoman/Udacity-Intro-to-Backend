#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import string
import cgi

form = """
<form method="post">
    What is your birthday?
    <br>

    <label>
        Month
        <input type="text" name="month" value="%(month)s">
    </label>

    <label>
        Day
        <input type="text" name="day" value="%(day)s">
    </label>

    <label>
        Year
        <input type="text" name="year" value="%(year)s">
    </label>

    <div style="color: red;">%(error)s</div>
    <br>
    <br>
    <input type="submit">
</form>
"""

class MainHandler(webapp2.RequestHandler):
    def write_form(self, error = "", month = "", day = "", year = ""):
        self.response.out.write(form % {'error': error,
                                        'month': escape_html(month),
                                        'day': escape_html(day),
                                        'year': escape_html(year)})

    def get(self):
        self.write_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_form("Invalid form data.", user_month, user_day, user_year)
        else:
            self.redirect("/thanks")

class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Thanks 4 valid data.")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/thanks', ThanksHandler)
], debug=True)

# helper functions

def escape_html(s):
    return cgi.escape(s, quote = True)

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

def valid_month(month):
    if month:
        month_caps = string.capitalize(str(month))
        if month_caps in months:
            return month_caps

def valid_day(day):
    if day:
        if str.isdigit(str(day)):
            digitday = int(day)
            if digitday in range(1, 32):
                return digitday

def valid_year(year):
    if year:
        if str.isdigit(str(year)):
            yeardigit = int(year)
            if yeardigit in range(1900, 2021):
                return yeardigit
