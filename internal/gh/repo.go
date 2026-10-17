// ©AngelaMos | 2026
// repo.go

package gh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	RepoSearchRequestsPerMinute = 30
	minRepoSearchInterval       = time.Minute / RepoSearchRequestsPerMinute
	repoSearchPageSize          = 100
	repoSearchMaxPages          = 10
)

type Repository struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	HTMLURL       string `json:"html_url"`
	Description   string `json:"description"`
	Language      string `json:"language"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	Stars         int    `json:"stargazers_count"`
	Forks         int    `json:"forks_count"`
	CreatedAt     string `json:"created_at"`
	PushedAt      string `json:"pushed_at"`
}

func (r Repository) Ref() string {
	if r.DefaultBranch == "" {
		return "HEAD"
	}
	return r.DefaultBranch
}

type repoSearchResult struct {
	TotalCount        int          `json:"total_count"`
	IncompleteResults bool         `json:"incomplete_results"`
	Items             []Repository `json:"items"`
}

type TreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type treeResponse struct {
	SHA       string      `json:"sha"`
	Tree      []TreeEntry `json:"tree"`
	Truncated bool        `json:"truncated"`
}

func (c *Client) SearchRepositories(ctx context.Context, query string, limit int) ([]Repository, int, error) {
	var (
		all   []Repository
		total int
	)

	for page := 1; page <= repoSearchMaxPages; page++ {
		perPage := repoSearchPageSize
		if limit > 0 && limit-len(all) < perPage {
			perPage = limit - len(all)
		}
		if perPage <= 0 {
			break
		}

		q := url.Values{}
		q.Set("q", query)
		q.Set("per_page", fmt.Sprint(perPage))
		q.Set("page", fmt.Sprint(page))

		req, err := c.newRequest(ctx, http.MethodGet, c.base+"/search/repositories?"+q.Encode(), "application/vnd.github+json")
		if err != nil {
			return all, total, err
		}

		body, err := c.do(ctx, req, c.repoSearchLim)
		c.countAPI()
		if err != nil {
			return all, total, err
		}

		var sr repoSearchResult
		if err := json.Unmarshal(body, &sr); err != nil {
			return all, total, fmt.Errorf("decode repository search response: %w", err)
		}
		total = sr.TotalCount
		all = append(all, sr.Items...)

		if len(sr.Items) < perPage {
			break
		}
		if limit > 0 && len(all) >= limit {
			break
		}
	}
	return all, total, nil
}

func (c *Client) ListOwnerRepos(ctx context.Context, owner string, limit int) ([]Repository, error) {
	var all []Repository

	for _, kind := range []string{"users", "orgs"} {
		all = all[:0]
		failed := false

		for page := 1; page <= 50; page++ {
			q := url.Values{}
			q.Set("per_page", fmt.Sprint(repoSearchPageSize))
			q.Set("page", fmt.Sprint(page))
			q.Set("type", "owner")

			req, err := c.newRequest(ctx, http.MethodGet,
				fmt.Sprintf("%s/%s/%s/repos?%s", c.base, kind, url.PathEscape(owner), q.Encode()),
				"application/vnd.github+json")
			if err != nil {
				return nil, err
			}

			body, err := c.do(ctx, req, c.fetchLim)
			c.countAPI()
			if err != nil {
				failed = true
				break
			}

			var batch []Repository
			if err := json.Unmarshal(body, &batch); err != nil {
				failed = true
				break
			}
			all = append(all, batch...)

			if len(batch) < repoSearchPageSize {
				break
			}
			if limit > 0 && len(all) >= limit {
				break
			}
		}

		if !failed && len(all) > 0 {
			break
		}
	}

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no repositories found for owner %q", owner)
	}
	out := make([]Repository, len(all))
	copy(out, all)
	return out, nil
}

func (c *Client) GetRepo(ctx context.Context, fullName string) (Repository, error) {
	var repo Repository

	req, err := c.newRequest(ctx, http.MethodGet, c.base+"/repos/"+fullName, "application/vnd.github+json")
	if err != nil {
		return repo, err
	}
	body, err := c.do(ctx, req, c.fetchLim)
	c.countAPI()
	if err != nil {
		return repo, err
	}
	if err := json.Unmarshal(body, &repo); err != nil {
		return repo, err
	}
	return repo, nil
}

func (c *Client) Tree(ctx context.Context, repo Repository) ([]TreeEntry, bool, error) {
	u := fmt.Sprintf("%s/repos/%s/git/trees/%s?recursive=1", c.base, repo.FullName, url.PathEscape(repo.Ref()))

	req, err := c.newRequest(ctx, http.MethodGet, u, "application/vnd.github+json")
	if err != nil {
		return nil, false, err
	}
	body, err := c.do(ctx, req, c.fetchLim)
	c.countAPI()
	if err != nil {
		return nil, false, err
	}

	var tr treeResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, false, fmt.Errorf("decode tree for %s: %w", repo.FullName, err)
	}

	blobs := make([]TreeEntry, 0, len(tr.Tree))
	for _, e := range tr.Tree {
		if e.Type == "blob" {
			blobs = append(blobs, e)
		}
	}
	return blobs, tr.Truncated, nil
}

func (c *Client) Blob(ctx context.Context, repo Repository, entry TreeEntry) ([]byte, string, error) {
	if data, ok := c.cache.GetRaw(entry.SHA); ok {
		c.mu.Lock()
		c.cacheHit++
		c.mu.Unlock()
		return data, "cache", nil
	}

	data, err := c.fetchRaw(ctx, repo.FullName, repo.Ref(), entry.Path)
	if err == nil && BlobSHA(data) == entry.SHA {
		c.store(entry.SHA, data)
		return data, "raw", nil
	}

	data, err = c.fetchBlob(ctx, repo.FullName, entry.SHA)
	if err != nil {
		return nil, "", err
	}
	c.store(entry.SHA, data)
	return data, "blob", nil
}

func (c *Client) countAPI() {
	c.mu.Lock()
	c.apiCalls++
	c.mu.Unlock()
}

func ParseSweepTarget(s string) (owner, repo string) {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "https://github.com/"), "/")
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 && parts[1] != "" {
		return parts[0], parts[1]
	}
	return parts[0], ""
}
