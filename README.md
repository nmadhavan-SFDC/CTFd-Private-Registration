# CTFd-Private-Registration
Plugin for private registration feature in CTFd so only invited teams (identified by unique token or email) can register.

![CTFd Private Registration.](http://i.imgur.com/xSxlGFu.png)

## Installation

Clone this repository to the [CTFd/plugins](https://github.com/isislab/CTFd/tree/master/CTFd/plugins) folder.

## Usage

1. Navigate to this plugin configuration panel in admin page.
2. In 'Option' tab, choose whether invited teams need to fill in a unique token or just the invited email address for registration.
3. In 'Invite' tab, upload CSV file with invited team name and email for each line.

   **Example**
   ```
   Team1,team1@email.com
   Team XYZ,teamxyz@email.com
   "Team,comma",teamcomma@email.com
   "Team,comma""quote""",teamcommaquote@email.com
   ```

4. In 'Invited Teams' tab, you can export invited teams and unique token for each team in CSV format. You can also remove the invitation or see which teams are already registered.
5. If you have configured Email in your CTFd installation, you can also automatically send invitation (with token if you choose 'invited teams need to fill a unique token') to all invited emails.

This plugin use modified registration page from [original](https://github.com/CTFd/CTFd/blob/master/CTFd/themes/original/templates/register.html) template of CTFd. You can modify [private-registration.html](https://gitlab.com/farisv/CTFd-Private-Registration/blob/master/privateregistration/templates/private-registration.html) to suit your needs.
