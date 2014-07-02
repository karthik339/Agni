# add Flask-related imports before this point
from flask.ext.login import LoginManager, login_user, UserMixin, \
    login_required, logout_user, current_user
from wtforms import Form, TextField, PasswordField, validators
# simpleldap is way more convenient than python-ldap
import simpleldap

# initialize the Flask app
app = Flask(__name__)

# initialize the login manager
login_manager = LoginManager()
login_manager.init_app(app)

ldapsrv = '173.36.129.204'
basedn = 'ou=active,ou=employees,ou=people,o=cisco.com'


def ldap_fetch(uid=None, name=None, passwd=None):
    try:
        if name is not None and passwd is not None:
            l = simpleldap.Connection(ldapsrv,
                dn='uid={0},{1}'.format(name, basedn), password=passwd)
            r = l.search('uid={0}'.format(name), base_dn=basedn)
        else:
            l = simpleldap.Connection(ldapsrv)
            r = l.search('uidNumber={0}'.format(uid), base_dn=basedn)

        return {
            'name': r[0]['uid'][0],
            'id': unicode(r[0]['uidNumber'][0]),
            'gid': int(r[0]['gidNumber'][0])
        }
    except:
        return None


class User(UserMixin):
    def __init__(self, uid=None, name=None, passwd=None):

        self.active = False

        ldapres = ldap_fetch(uid=uid, name=name, passwd=passwd)

        if ldapres is not None:
            self.name = ldapres['name']
            self.id = ldapres['id']
            # assume that a disabled user belongs to group 404
            if ldapres['gid'] != 404:
                self.active = True
            self.gid = ldapres['gid']

    def is_active(self):
        return self.active

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(userid):
    return User(uid=userid)


class LoginForm(Form):
    username = TextField("Username", [validators.Length(min=2, max=25)])
    password = PasswordField('Password', [validators.Required()])


@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(name=form.username.data, passwd=form.password.data)
        if user.active is not False:
            login_user(user)
            flash("Logged in successfully.")
            return redirect(url_for("some_secret_page"))
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
