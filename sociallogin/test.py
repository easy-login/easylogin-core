class Parent(object):
    def greeting(self):
        return 'hello, ' + self._name()

    def _name(self):
        return 'abu'

class Child(Parent):
    def _name(self):
        return 'tjeubaoit'

o = Child()
print(o.greeting())