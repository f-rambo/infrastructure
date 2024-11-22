package biz

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cast"
)

func (c *Cluster) GetCloudResource(resourceType ResourceType) []*CloudResource {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources != nil && resources.Type == resourceType {
			cloudResources = append(cloudResources, resources)
		}
	}
	return cloudResources
}

func (c *Cluster) AddCloudResource(resource *CloudResource) {
	if resource == nil {
		return
	}
	if c.CloudResources == nil {
		c.CloudResources = make([]*CloudResource, 0)
	}
	if resource.Id == "" {
		resource.Id = uuid.New().String()
	}
	c.CloudResources = append(c.CloudResources, resource)
}

func (c *Cluster) AddSubCloudResource(resourceType ResourceType, parentID string, resource *CloudResource) {
	cloudResource := c.GetCloudResourceByID(resourceType, parentID)
	if cloudResource == nil {
		return
	}
	if cloudResource.SubResources == nil {
		cloudResource.SubResources = make([]*CloudResource, 0)
	}
	resource.Type = resourceType
	if resource.Id == "" {
		resource.Id = uuid.New().String()
	}
	cloudResource.SubResources = append(cloudResource.SubResources, resource)
}

func (c *Cluster) GetCloudResourceByName(resourceType ResourceType, name string) *CloudResource {
	for _, resource := range c.CloudResources {
		if resource.Type == resourceType && resource.Name == name {
			return resource
		}
	}
	return nil
}

func (c *Cluster) GetCloudResourceByID(resourceType ResourceType, id string) *CloudResource {
	resource := getCloudResourceByID(c.GetCloudResource(resourceType), id)
	if resource != nil {
		return resource
	}
	return nil
}

func (c *Cluster) GetCloudResourceByRefID(resourceType ResourceType, refID string) *CloudResource {
	for _, resource := range c.CloudResources {
		if resource.Type == resourceType && resource.RefId == refID {
			return resource
		}
	}
	return nil
}

func getCloudResourceByID(cloudResources []*CloudResource, id string) *CloudResource {
	for _, resource := range cloudResources {
		if resource.Id == id {
			return resource
		}
		if len(resource.SubResources) > 0 {
			subResource := getCloudResourceByID(resource.SubResources, id)
			if subResource != nil {
				return subResource
			}
		}
	}
	return nil
}

func (c *Cluster) GetSingleCloudResource(resourceType ResourceType) *CloudResource {
	resources := c.GetCloudResource(resourceType)
	if len(resources) == 0 {
		return nil
	}
	return resources[0]
}

// getCloudResource by resourceType and tag value and tag key
func (c *Cluster) GetCloudResourceByTags(resourceType ResourceType, tagKeyValues ...string) []*CloudResource {
	if len(tagKeyValues)%2 != 0 {
		return nil
	}
	cloudResources := make([]*CloudResource, 0)
	for _, resource := range c.GetCloudResource(resourceType) {
		if resource.Tags == "" {
			continue
		}
		resourceTagsMap := c.DecodeTags(resource.Tags)
		match := true
		for i := 0; i < len(tagKeyValues); i += 2 {
			tagKey := tagKeyValues[i]
			tagValue := tagKeyValues[i+1]
			if resourceTagsMap[tagKey] != tagValue {
				match = false
				break
			}
		}
		if match {
			cloudResources = append(cloudResources, resource)
		}
	}
	if len(cloudResources) == 0 {
		return nil
	}
	return cloudResources
}

func (c *Cluster) EncodeTags(tags map[string]string) string {
	tagStr := ""
	for key, value := range tags {
		tagStr += fmt.Sprintf("%s:%s,", key, value)
	}
	return tagStr
}

func (c *Cluster) DecodeTags(tags string) map[string]string {
	tagsMap := make(map[string]string)
	for _, tag := range strings.Split(tags, ",") {
		tagKeyValue := strings.Split(tag, ":")
		if len(tagKeyValue) != 2 {
			continue
		}
		tagsMap[tagKeyValue[0]] = tagKeyValue[1]
	}
	return tagsMap
}

// delete cloud resource by resourceType
func (c *Cluster) DeleteCloudResource(resourceType ResourceType) {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources.Type != resourceType {
			cloudResources = append(cloudResources, resources)
		}
	}
	c.CloudResources = cloudResources
}

// delete cloud resource by resourceType and id
func (c *Cluster) DeleteCloudResourceByID(resourceType ResourceType, id string) {
	cloudResources := make([]*CloudResource, 0)
	for _, resources := range c.CloudResources {
		if resources.Type == resourceType && resources.Id != id {
			cloudResources = append(cloudResources, resources)
		}
	}
	c.CloudResources = cloudResources
}

// delete cloud resource by resourceType and tag value and tag key
func (c *Cluster) DeleteCloudResourceByTags(resourceType ResourceType, tagKeyValues ...string) {
	cloudResources := make([]*CloudResource, 0)
	for _, resource := range c.CloudResources {
		if resource.Tags == "" {
			continue
		}
		match := true
		resourceTagsMap := c.DecodeTags(resource.Tags)
		for i := 0; i < len(tagKeyValues); i += 2 {
			tagKey := tagKeyValues[i]
			tagValue := tagKeyValues[i+1]
			if resourceTagsMap[tagKey] != tagValue {
				match = false
				break
			}
		}
		if match {
			continue
		}
		cloudResources = append(cloudResources, resource)
	}
	c.CloudResources = cloudResources
}

func (c *Cluster) GenerateNodeGroupName(nodeGroup *NodeGroup) {
	nodeGroup.Name = strings.Join([]string{
		c.Name,
		nodeGroup.Type.String(),
		nodeGroup.Os,
		nodeGroup.Arch,
		cast.ToString(nodeGroup.Cpu),
		cast.ToString(nodeGroup.Memory),
		cast.ToString(nodeGroup.Gpu),
		cast.ToString(nodeGroup.GpuSpec),
	}, "-")
}

func (c ClusterType) IsCloud() bool {
	return c != ClusterType_LOCAL
}

func (c ClusterType) IsIntegratedCloud() bool {
	return c == ClusterType_AWS_EKS || c == ClusterType_ALICLOUD_AKS
}

func (ng *NodeGroup) SetTargetSize(size int32) {
	ng.TargetSize = size
}

type NodeGroups []*NodeGroup

func (n NodeGroups) Len() int {
	return len(n)
}

func (n NodeGroups) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func (n NodeGroups) Less(i, j int) bool {
	if n[i] == nil || n[j] == nil {
		return false
	}
	if n[i].Memory == n[j].Memory {
		return n[i].Cpu < n[j].Cpu
	}
	return n[i].Memory < n[j].Memory
}

func (c *Cluster) GetNodeGroup(nodeGroupId string) *NodeGroup {
	for _, nodeGroup := range c.NodeGroups {
		if nodeGroup.Id == nodeGroupId {
			return nodeGroup
		}
	}
	return nil
}

func (c *Cluster) GetNodeGroupByName(nodeGroupName string) *NodeGroup {
	for _, nodeGroup := range c.NodeGroups {
		if nodeGroup.Name == nodeGroupName {
			return nodeGroup
		}
	}
	return nil
}
