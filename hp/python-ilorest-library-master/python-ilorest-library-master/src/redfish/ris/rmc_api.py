from rmc import RmcApp

class Rmc_API(RmcApp):
    def __init__(self, Args=None):
        RmcApp.__init__(self, Args)

    def Api_login(self, url=None, username=None, password=None):
        self.login(base_url=url, username=username, password=password)

#for testing
if __name__ == '__main__':
    api = Rmc_API()
    api.do_stuff()