// +build !ignore_autogenerated

//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by operator-sdk. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditServiceSpec) DeepCopyInto(out *AuditServiceSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditServiceSpec.
func (in *AuditServiceSpec) DeepCopy() *AuditServiceSpec {
	if in == nil {
		return nil
	}
	out := new(AuditServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuthServiceSpec) DeepCopyInto(out *AuthServiceSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthServiceSpec.
func (in *AuthServiceSpec) DeepCopy() *AuthServiceSpec {
	if in == nil {
		return nil
	}
	out := new(AuthServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Authentication) DeepCopyInto(out *Authentication) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Authentication.
func (in *Authentication) DeepCopy() *Authentication {
	if in == nil {
		return nil
	}
	out := new(Authentication)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Authentication) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuthenticationList) DeepCopyInto(out *AuthenticationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Authentication, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthenticationList.
func (in *AuthenticationList) DeepCopy() *AuthenticationList {
	if in == nil {
		return nil
	}
	out := new(AuthenticationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AuthenticationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuthenticationSpec) DeepCopyInto(out *AuthenticationSpec) {
	*out = *in
	in.AuditService.DeepCopyInto(&out.AuditService)
	in.AuthService.DeepCopyInto(&out.AuthService)
	in.IdentityProvider.DeepCopyInto(&out.IdentityProvider)
	in.IdentityManager.DeepCopyInto(&out.IdentityManager)
	in.InitMongodb.DeepCopyInto(&out.InitMongodb)
	in.ClientRegistration.DeepCopyInto(&out.ClientRegistration)
	out.Config = in.Config
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthenticationSpec.
func (in *AuthenticationSpec) DeepCopy() *AuthenticationSpec {
	if in == nil {
		return nil
	}
	out := new(AuthenticationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuthenticationStatus) DeepCopyInto(out *AuthenticationStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthenticationStatus.
func (in *AuthenticationStatus) DeepCopy() *AuthenticationStatus {
	if in == nil {
		return nil
	}
	out := new(AuthenticationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Client) DeepCopyInto(out *Client) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Client.
func (in *Client) DeepCopy() *Client {
	if in == nil {
		return nil
	}
	out := new(Client)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Client) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientList) DeepCopyInto(out *ClientList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Client, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientList.
func (in *ClientList) DeepCopy() *ClientList {
	if in == nil {
		return nil
	}
	out := new(ClientList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClientList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientRegistrationSpec) DeepCopyInto(out *ClientRegistrationSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientRegistrationSpec.
func (in *ClientRegistrationSpec) DeepCopy() *ClientRegistrationSpec {
	if in == nil {
		return nil
	}
	out := new(ClientRegistrationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientSpec) DeepCopyInto(out *ClientSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientSpec.
func (in *ClientSpec) DeepCopy() *ClientSpec {
	if in == nil {
		return nil
	}
	out := new(ClientSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientStatus) DeepCopyInto(out *ClientStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientStatus.
func (in *ClientStatus) DeepCopy() *ClientStatus {
	if in == nil {
		return nil
	}
	out := new(ClientStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConfigSpec) DeepCopyInto(out *ConfigSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConfigSpec.
func (in *ConfigSpec) DeepCopy() *ConfigSpec {
	if in == nil {
		return nil
	}
	out := new(ConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IAMOnboardingSpec) DeepCopyInto(out *IAMOnboardingSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IAMOnboardingSpec.
func (in *IAMOnboardingSpec) DeepCopy() *IAMOnboardingSpec {
	if in == nil {
		return nil
	}
	out := new(IAMOnboardingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityManagerSpec) DeepCopyInto(out *IdentityManagerSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityManagerSpec.
func (in *IdentityManagerSpec) DeepCopy() *IdentityManagerSpec {
	if in == nil {
		return nil
	}
	out := new(IdentityManagerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityProviderSpec) DeepCopyInto(out *IdentityProviderSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderSpec.
func (in *IdentityProviderSpec) DeepCopy() *IdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonationSpec) DeepCopyInto(out *ImpersonationSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonationSpec.
func (in *ImpersonationSpec) DeepCopy() *ImpersonationSpec {
	if in == nil {
		return nil
	}
	out := new(ImpersonationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitAuthServiceSpec) DeepCopyInto(out *InitAuthServiceSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitAuthServiceSpec.
func (in *InitAuthServiceSpec) DeepCopy() *InitAuthServiceSpec {
	if in == nil {
		return nil
	}
	out := new(InitAuthServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitIdentityManagerSpec) DeepCopyInto(out *InitIdentityManagerSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitIdentityManagerSpec.
func (in *InitIdentityManagerSpec) DeepCopy() *InitIdentityManagerSpec {
	if in == nil {
		return nil
	}
	out := new(InitIdentityManagerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitIdentityProviderSpec) DeepCopyInto(out *InitIdentityProviderSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitIdentityProviderSpec.
func (in *InitIdentityProviderSpec) DeepCopy() *InitIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(InitIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitMongodbSpec) DeepCopyInto(out *InitMongodbSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitMongodbSpec.
func (in *InitMongodbSpec) DeepCopy() *InitMongodbSpec {
	if in == nil {
		return nil
	}
	out := new(InitMongodbSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitPAPSpec) DeepCopyInto(out *InitPAPSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitPAPSpec.
func (in *InitPAPSpec) DeepCopy() *InitPAPSpec {
	if in == nil {
		return nil
	}
	out := new(InitPAPSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InitTokenServiceSpec) DeepCopyInto(out *InitTokenServiceSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InitTokenServiceSpec.
func (in *InitTokenServiceSpec) DeepCopy() *InitTokenServiceSpec {
	if in == nil {
		return nil
	}
	out := new(InitTokenServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientWatcher) DeepCopyInto(out *OIDCClientWatcher) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientWatcher.
func (in *OIDCClientWatcher) DeepCopy() *OIDCClientWatcher {
	if in == nil {
		return nil
	}
	out := new(OIDCClientWatcher)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OIDCClientWatcher) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientWatcherList) DeepCopyInto(out *OIDCClientWatcherList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]OIDCClientWatcher, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientWatcherList.
func (in *OIDCClientWatcherList) DeepCopy() *OIDCClientWatcherList {
	if in == nil {
		return nil
	}
	out := new(OIDCClientWatcherList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OIDCClientWatcherList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientWatcherSpec) DeepCopyInto(out *OIDCClientWatcherSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	in.OidcInitAuthService.DeepCopyInto(&out.OidcInitAuthService)
	in.OidcInitIdentityProvider.DeepCopyInto(&out.OidcInitIdentityProvider)
	in.OidcInitIdentityManager.DeepCopyInto(&out.OidcInitIdentityManager)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientWatcherSpec.
func (in *OIDCClientWatcherSpec) DeepCopy() *OIDCClientWatcherSpec {
	if in == nil {
		return nil
	}
	out := new(OIDCClientWatcherSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClientWatcherStatus) DeepCopyInto(out *OIDCClientWatcherStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClientWatcherStatus.
func (in *OIDCClientWatcherStatus) DeepCopy() *OIDCClientWatcherStatus {
	if in == nil {
		return nil
	}
	out := new(OIDCClientWatcherStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OidcInitAuthServiceSpec) DeepCopyInto(out *OidcInitAuthServiceSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OidcInitAuthServiceSpec.
func (in *OidcInitAuthServiceSpec) DeepCopy() *OidcInitAuthServiceSpec {
	if in == nil {
		return nil
	}
	out := new(OidcInitAuthServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OidcInitIdentityManagerSpec) DeepCopyInto(out *OidcInitIdentityManagerSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OidcInitIdentityManagerSpec.
func (in *OidcInitIdentityManagerSpec) DeepCopy() *OidcInitIdentityManagerSpec {
	if in == nil {
		return nil
	}
	out := new(OidcInitIdentityManagerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OidcInitIdentityProviderSpec) DeepCopyInto(out *OidcInitIdentityProviderSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OidcInitIdentityProviderSpec.
func (in *OidcInitIdentityProviderSpec) DeepCopy() *OidcInitIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(OidcInitIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Pap) DeepCopyInto(out *Pap) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Pap.
func (in *Pap) DeepCopy() *Pap {
	if in == nil {
		return nil
	}
	out := new(Pap)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Pap) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PapList) DeepCopyInto(out *PapList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Pap, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PapList.
func (in *PapList) DeepCopy() *PapList {
	if in == nil {
		return nil
	}
	out := new(PapList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PapList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PapServiceSpec) DeepCopyInto(out *PapServiceSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PapServiceSpec.
func (in *PapServiceSpec) DeepCopy() *PapServiceSpec {
	if in == nil {
		return nil
	}
	out := new(PapServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PapSpec) DeepCopyInto(out *PapSpec) {
	*out = *in
	in.PapService.DeepCopyInto(&out.PapService)
	in.AuditService.DeepCopyInto(&out.AuditService)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PapSpec.
func (in *PapSpec) DeepCopy() *PapSpec {
	if in == nil {
		return nil
	}
	out := new(PapSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PapStatus) DeepCopyInto(out *PapStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PapStatus.
func (in *PapStatus) DeepCopy() *PapStatus {
	if in == nil {
		return nil
	}
	out := new(PapStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyController) DeepCopyInto(out *PolicyController) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyController.
func (in *PolicyController) DeepCopy() *PolicyController {
	if in == nil {
		return nil
	}
	out := new(PolicyController)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolicyController) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyControllerConfigSpec) DeepCopyInto(out *PolicyControllerConfigSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyControllerConfigSpec.
func (in *PolicyControllerConfigSpec) DeepCopy() *PolicyControllerConfigSpec {
	if in == nil {
		return nil
	}
	out := new(PolicyControllerConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyControllerList) DeepCopyInto(out *PolicyControllerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]PolicyController, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyControllerList.
func (in *PolicyControllerList) DeepCopy() *PolicyControllerList {
	if in == nil {
		return nil
	}
	out := new(PolicyControllerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolicyControllerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyControllerSpec) DeepCopyInto(out *PolicyControllerSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	out.Config = in.Config
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyControllerSpec.
func (in *PolicyControllerSpec) DeepCopy() *PolicyControllerSpec {
	if in == nil {
		return nil
	}
	out := new(PolicyControllerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyControllerStatus) DeepCopyInto(out *PolicyControllerStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyControllerStatus.
func (in *PolicyControllerStatus) DeepCopy() *PolicyControllerStatus {
	if in == nil {
		return nil
	}
	out := new(PolicyControllerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyDecision) DeepCopyInto(out *PolicyDecision) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyDecision.
func (in *PolicyDecision) DeepCopy() *PolicyDecision {
	if in == nil {
		return nil
	}
	out := new(PolicyDecision)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolicyDecision) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyDecisionList) DeepCopyInto(out *PolicyDecisionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]PolicyDecision, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyDecisionList.
func (in *PolicyDecisionList) DeepCopy() *PolicyDecisionList {
	if in == nil {
		return nil
	}
	out := new(PolicyDecisionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolicyDecisionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyDecisionSpec) DeepCopyInto(out *PolicyDecisionSpec) {
	*out = *in
	in.AuditService.DeepCopyInto(&out.AuditService)
	in.InitMongodb.DeepCopyInto(&out.InitMongodb)
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyDecisionSpec.
func (in *PolicyDecisionSpec) DeepCopy() *PolicyDecisionSpec {
	if in == nil {
		return nil
	}
	out := new(PolicyDecisionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyDecisionStatus) DeepCopyInto(out *PolicyDecisionStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyDecisionStatus.
func (in *PolicyDecisionStatus) DeepCopy() *PolicyDecisionStatus {
	if in == nil {
		return nil
	}
	out := new(PolicyDecisionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretWatcher) DeepCopyInto(out *SecretWatcher) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretWatcher.
func (in *SecretWatcher) DeepCopy() *SecretWatcher {
	if in == nil {
		return nil
	}
	out := new(SecretWatcher)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecretWatcher) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretWatcherConfigSpec) DeepCopyInto(out *SecretWatcherConfigSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretWatcherConfigSpec.
func (in *SecretWatcherConfigSpec) DeepCopy() *SecretWatcherConfigSpec {
	if in == nil {
		return nil
	}
	out := new(SecretWatcherConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretWatcherList) DeepCopyInto(out *SecretWatcherList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SecretWatcher, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretWatcherList.
func (in *SecretWatcherList) DeepCopy() *SecretWatcherList {
	if in == nil {
		return nil
	}
	out := new(SecretWatcherList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecretWatcherList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretWatcherSpec) DeepCopyInto(out *SecretWatcherSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	out.Config = in.Config
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretWatcherSpec.
func (in *SecretWatcherSpec) DeepCopy() *SecretWatcherSpec {
	if in == nil {
		return nil
	}
	out := new(SecretWatcherSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretWatcherStatus) DeepCopyInto(out *SecretWatcherStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretWatcherStatus.
func (in *SecretWatcherStatus) DeepCopy() *SecretWatcherStatus {
	if in == nil {
		return nil
	}
	out := new(SecretWatcherStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityOnboarding) DeepCopyInto(out *SecurityOnboarding) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityOnboarding.
func (in *SecurityOnboarding) DeepCopy() *SecurityOnboarding {
	if in == nil {
		return nil
	}
	out := new(SecurityOnboarding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecurityOnboarding) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityOnboardingList) DeepCopyInto(out *SecurityOnboardingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SecurityOnboarding, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityOnboardingList.
func (in *SecurityOnboardingList) DeepCopy() *SecurityOnboardingList {
	if in == nil {
		return nil
	}
	out := new(SecurityOnboardingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SecurityOnboardingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityOnboardingSpec) DeepCopyInto(out *SecurityOnboardingSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(v1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	in.IAMOnboarding.DeepCopyInto(&out.IAMOnboarding)
	in.InitAuthService.DeepCopyInto(&out.InitAuthService)
	in.InitIdentityProvider.DeepCopyInto(&out.InitIdentityProvider)
	in.InitIdentityManager.DeepCopyInto(&out.InitIdentityManager)
	in.InitTokenService.DeepCopyInto(&out.InitTokenService)
	in.InitPAP.DeepCopyInto(&out.InitPAP)
	out.Config = in.Config
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityOnboardingSpec.
func (in *SecurityOnboardingSpec) DeepCopy() *SecurityOnboardingSpec {
	if in == nil {
		return nil
	}
	out := new(SecurityOnboardingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityOnboardingStatus) DeepCopyInto(out *SecurityOnboardingStatus) {
	*out = *in
	if in.PodNames != nil {
		in, out := &in.PodNames, &out.PodNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityOnboardingStatus.
func (in *SecurityOnboardingStatus) DeepCopy() *SecurityOnboardingStatus {
	if in == nil {
		return nil
	}
	out := new(SecurityOnboardingStatus)
	in.DeepCopyInto(out)
	return out
}
