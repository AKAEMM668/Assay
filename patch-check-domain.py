with open('internal/mechanics/check_domain.go', 'r') as f:
    code = f.read()

# Issue 4: domain mismatch
if 's.Directory != nil && s.Directory.Domain != "" && s.Directory.Domain != domain' not in code:
    insertion = """
	if domain != "" && s.Directory != nil && s.Directory.Domain != "" && s.Directory.Domain != domain {
		f.Reasoning = fmt.Sprintf("The issuer advertises home_domain %q, but the curated directory lists it under %q. " +
			"This discrepancy means accountability is unverified, as it is unclear which domain truly claims this asset.", domain, s.Directory.Domain)
		acc = AccountabilityUnverified
		f.Accountability = &acc
		f.Evidence = append(f.Evidence, Evidence{
			Source: "home_domain",
			Claim: domain,
		})
		f.Evidence = append(f.Evidence, Evidence{
			Source: "directory",
			Claim: s.Directory.Domain,
		})
		return f, nil
	}
"""
    # Insert after if domain == ""
    target = "return f, nil\n\t}"
    idx = code.find(target)
    if idx != -1:
        idx += len(target)
        code = code[:idx] + insertion + code[idx:]
        print("Patched domain mismatch")
        
with open('internal/mechanics/check_domain.go', 'w') as f:
    f.write(code)
