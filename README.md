# Pwntools Blog

## Setup and Requirements

This blog is based on Hugo, and requires Pygments to be installed for syntax highlighting.

### macOS Installation

```sh
brew install hugo pygments
```

## Creating a New Blog Post

```
hugo new posts/your-post-name.md
vim posts/your-post-name.md
```

## Publishing a New Article

First, in the Front End Matter of the post, set `draft` to `false`.

Next, commit the article to Git and push it to GitHub.  An automatic GitHub Action should take care of everything else, and automagically render and publish the raw HTML to `blog.pwntools.com`.

## Colorized Script Output

In order to get colorized output into the blog post, you'll need a command that looks like this:

```
PWNLIB_COLOR=always python3 exploit.py DEBUG | ansifilter --encoding=utf-8 --html --fragment -o output.html
```

Copy the contents of the output HTML document into the blog post, and surround with a `rawhtml` block.

```
{{< rawhtml >}}
Paste contents here
{{< /rawhtml >}}
```
