#ifndef __BSR_NLA_H
#define __BSR_NLA_H

extern int bsr_nla_parse_nested(struct nlattr *tb[], int maxtype, struct nlattr *nla,
				 const struct nla_policy *policy);
extern struct nlattr *bsr_nla_find_nested(int maxtype, struct nlattr *nla, int attrtype);

#endif  /* __BSR_NLA_H */
