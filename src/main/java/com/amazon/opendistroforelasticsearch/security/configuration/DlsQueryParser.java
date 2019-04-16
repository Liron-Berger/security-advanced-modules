/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.configuration;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.BooleanClause.Occur;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.PrefixQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.join.BitSetProducer;
import org.apache.lucene.search.join.ToChildBlockJoinQuery;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.query.AbstractQueryBuilder;
import org.elasticsearch.index.query.ParsedQuery;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryShardContext;

import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;


import org.apache.logging.log4j.Logger;


final class DlsQueryParser {

    private static final Query NON_NESTED_QUERY;

    static {
        //Match all documents but not the nested ones
        //Nested document types start with __
        //https://discuss.elastic.co/t/whats-nested-documents-layout-inside-the-lucene/59944/9
        NON_NESTED_QUERY = new BooleanQuery.Builder()
        .add(new MatchAllDocsQuery(), Occur.FILTER)
        .add(new PrefixQuery(new Term("_type", "__")), Occur.MUST_NOT)
        .build();
    }


    private static Cache<String, QueryBuilder> queries = CacheBuilder.newBuilder().maximumSize(10000).expireAfterWrite(4, TimeUnit.HOURS)
            .build();

    private DlsQueryParser() {

    }

    static Query parse(final Set<String> unparsedDlsQueries, final QueryShardContext queryShardContext,
            final NamedXContentRegistry namedXContentRegistry) throws IOException {
        final Logger logger = LogManager.getLogger("DlsQueryParser.parse");

        if (unparsedDlsQueries == null || unparsedDlsQueries.isEmpty()) {
            return null;
        }

        final boolean hasNestedMapping = queryShardContext.getMapperService().hasNested();

        BooleanQuery.Builder dlsQueryBuilder = new BooleanQuery.Builder();
        dlsQueryBuilder.setMinimumNumberShouldMatch(1);

        for (final String unformattedDlsQuery : unparsedDlsQueries) {

            String unparsedDlsQuery = handleListWithQuotes(unformattedDlsQuery);

            logger.debug("unformatted: " + unformattedDlsQuery + "\n" + "formatted: " + unparsedDlsQuery);
            
            try {

                final QueryBuilder qb = queries.get(unparsedDlsQuery, new Callable<QueryBuilder>() {

                    @Override
                    public QueryBuilder call() throws Exception {
                        final XContentParser parser = JsonXContent.jsonXContent.createParser(namedXContentRegistry, OpenDistroSecurityDeprecationHandler.INSTANCE, unparsedDlsQuery);
                        final QueryBuilder qb = AbstractQueryBuilder.parseInnerQueryBuilder(parser);
                        return qb;
                    }

                });
                final ParsedQuery parsedQuery = queryShardContext.toFilter(qb);
                final Query dlsQuery = parsedQuery.query();
                dlsQueryBuilder.add(dlsQuery, Occur.SHOULD);

                if (hasNestedMapping) {
                    handleNested(queryShardContext, dlsQueryBuilder, dlsQuery);
                }

            } catch (ExecutionException e) {
                    throw new IOException(e);
            }
        }

        // no need for scoring here, so its possible to wrap this in a
        // ConstantScoreQuery
        return new ConstantScoreQuery(dlsQueryBuilder.build());

    }

    private static void handleNested(final QueryShardContext queryShardContext,
            final BooleanQuery.Builder dlsQueryBuilder,
            final Query parentQuery) {
        final BitSetProducer parentDocumentsFilter = queryShardContext.bitsetFilter(NON_NESTED_QUERY);
        dlsQueryBuilder.add(new ToChildBlockJoinQuery(parentQuery, parentDocumentsFilter), Occur.SHOULD);
    }


    private static String handleListWithQuotes(String unparsedDlsQuery) {
        String patternString = "\"authorized_cns.raw\": \\[";
        String barcketCloser = "\\]";

        Pattern pattern = Pattern.compile(patternString);
        Pattern bracket = Pattern.compile(barcketCloser);

        Matcher matcher = pattern.matcher(unparsedDlsQuery);

        int count = 0;

        while(matcher.find()) {
            count++;

            String authorized_to_end = unparsedDlsQuery.substring(matcher.end(), unparsedDlsQuery.length());
            Matcher authorized_matcher = bracket.matcher(authorized_to_end);
            authorized_matcher.find();

            String authorized_cns = authorized_to_end.substring(0, authorized_matcher.start());

            for (String cn : authorized_cns.split(",")) {
                cn = cn.substring(1, cn.length() - 1);
                System.out.println(cn.replace("\"", "\\\""));
                unparsedDlsQuery = unparsedDlsQuery.replace(cn, cn.replace("\"", "\\\""));
            }
        }
        return unparsedDlsQuery;
    }
}
