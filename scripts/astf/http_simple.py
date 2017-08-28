from trex_astf_lib.api import ASTFProfile, ASTFCapInfo, ASTFIPGenDist, ASTFIPGen


class Prof1():
    def __init__(self):
        pass

    def get_profile(self):
        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.1", "16.0.0.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.0.255.255"], distribution="seq")
        ip_gen = ASTFIPGen(dist_client=ip_gen_c, dist_server=ip_gen_s)

        return ASTFProfile(default_ip_gen=ip_gen, cap_list=[ASTFCapInfo(file="../avl/delay_10_http_browsing_0.pcap")])


def register():
    return Prof1()
