# Terraform Module: k8s

Creates managed Kubernetes (EKS/GKE/AKS) or provisions k3s on IaaS. Installs metrics-server, ingress, cert-manager.

Inputs: region, node_groups, version. Outputs: cluster_endpoint, kubeconfig.
